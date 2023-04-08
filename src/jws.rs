//! Implementation of JSON Web Signature (JWS) as defined in [RFC 7515]
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>

use alloc::string::String;

use base64ct::{Base64UrlUnpadded, Encoding};
use thiserror_no_std::Error;

use crate::{
    format::{Compact, DecodeFormat, Format, JsonFlattened},
    header,
    jwa::JsonWebSigningAlgorithm,
    Base64UrlString, JoseHeader,
};

mod sign;
mod verify;

#[doc(inline)]
pub use {sign::*, verify::*};

// FIXME: check section 5.3. (string comparison) and verify correctness
// FIXME: Appendix F: Detached Content
// FIXME: protected headers

/// Different interpretations of a JWS payload.
// FIXME: unencoded payload (IMPORTANT: check that string is all ascii, except `.` character)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum PayloadKind {
    /// The given base64 string will just be used as the payload.
    Standard(Base64UrlString),
}

/// Represents anything that can be serialized to a raw payload.
///
/// This is required to be implemented when trying to sign a JWS, or encrypt a
/// JWE.
///
/// # Examples
///
/// ```
/// # extern crate alloc;
/// # use alloc::string::{FromUtf8Error, String};
/// # use core::convert::Infallible;
/// # use jose::Base64UrlString;
/// # use jose::jws::{FromRawPayload, ProvidePayload, PayloadKind};
///
/// #[derive(Debug, PartialEq, Eq)]
/// struct StringPayload(String);
///
/// impl ProvidePayload for StringPayload {
///     type Error = Infallible;
///
///     fn provide_payload<D: digest::Update>(
///         &mut self,
///         digest: &mut D,
///     ) -> Result<PayloadKind, Self::Error> {
///         let s = Base64UrlString::encode(&self.0);
///         digest.update(s.as_bytes());
///         Ok(PayloadKind::Standard(s))
///     }
/// }
/// ```
pub trait ProvidePayload {
    /// The error that can occurr while providing the payload in the
    /// [`Self::provide_payload`] method.
    type Error;

    /// First, this method must insert the raw bytes representation of this
    /// payload into the given `digest`, which is later used for creating the
    /// signature. Then the method must return the [kind of
    /// payload](PayloadKind) to use in the resulting JWS.
    ///
    /// # Errors
    ///
    /// Returns an error if it failed to provide the payload.
    fn provide_payload<D: digest::Update>(
        &mut self,
        digest: &mut D,
    ) -> Result<PayloadKind, Self::Error>;
}

impl<P: ProvidePayload> ProvidePayload for &mut P {
    type Error = P::Error;

    fn provide_payload<D: digest::Update>(
        &mut self,
        digest: &mut D,
    ) -> Result<PayloadKind, Self::Error> {
        <P as ProvidePayload>::provide_payload(self, digest)
    }
}

/// Represents anything that can be parsed from a raw payload.
///
/// This is required to be implemented when trying to decoe a JWS, or encrypt a
/// JWE, from it's format representation.
pub trait FromRawPayload: Sized {
    /// The error that can occurr in the [`Self::from_raw_payload`] method.
    type Error;

    /// Converts a raw [`PayloadKind`] enum into this payload type.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation failed.
    fn from_raw_payload(payload: PayloadKind) -> Result<Self, Self::Error>;
}

/// Different kinds of errors that can occurr while signing a JWS.
#[derive(Debug, Error)]
pub enum SignError<P> {
    /// Failed to serialize the [`JoseHeader`](crate::header::JoseHeader).
    #[error("failed to serialize header: {0}")]
    SerializeHeader(#[source] serde_json::Error),
    /// The header of the JWS is invalid.
    #[error("invalid JWS header: {0}")]
    InvalidHeader(#[source] header::Error),
    /// The header got invalid after updating it with the given signer.
    #[error("invalid JWS header after updating it with the given signer: {0}")]
    InvalidHeaderBuilder(#[source] header::JoseHeaderBuilderError),
    /// The underlying signing operation of the given signer failed.
    #[error(transparent)]
    Sign(signature::Error),
    /// Failed to convert payload into it's raw byte representation.
    #[error(transparent)]
    Payload(P),
}

#[derive(Debug)]
pub struct JsonWebSignature<F: Format, T> {
    header: F::JwsHeader,
    payload: T,
}

impl<T> JsonWebSignature<Compact, T> {
    pub fn new(payload: T) -> Self {
        let header = JoseHeader::<Compact, header::Jws>::builder()
            .algorithm(header::HeaderValue::Protected(
                JsonWebSigningAlgorithm::None,
            ))
            .build()
            .expect("this header is always valid");

        Self { header, payload }
    }

    pub fn new_with_header(header: JoseHeader<Compact, header::Jws>, payload: T) -> Self {
        Self { header, payload }
    }
}

impl<F: Format, T> JsonWebSignature<F, T> {
    /// Returns a reference to the payload of this JWS.
    pub fn payload(&self) -> &T {
        &self.payload
    }
}

impl<T> JsonWebSignature<Compact, T> {
    /// Returns a reference to the [`JoseHeader`](crate::header::JoseHeader) of this JWS.
    pub fn header(&self) -> &JoseHeader<Compact, header::Jws> {
        &self.header
    }
}

impl<F: Format, T: ProvidePayload> JsonWebSignature<F, T> {
    /// Signs this [`JsonWebSignature`] using the given `signer`.
    ///
    /// # Errors
    ///
    /// Returns an error if any step of the signing operation failed.
    /// This may include:
    /// - The header is invalid or failed to serialize.
    /// - The header is invalid after updating it with the given signer.
    /// - The underlying signing operation of the given signer failed.
    /// - The payload failed to provide it's raw byte representation.
    pub fn sign<S: AsRef<[u8]>, D: digest::Update>(
        mut self,
        signer: &mut dyn Signer<S, Digest = D>,
    ) -> Result<Signed<F>, SignError<T::Error>> {
        self.header =
            F::update_header(self.header, signer).map_err(SignError::InvalidHeaderBuilder)?;

        let mut digest = signer.new_digest();
        let serialized_header =
            F::provide_header(self.header, &mut digest).map_err(|x| match x {
                SignError::SerializeHeader(x) => SignError::SerializeHeader(x),
                SignError::InvalidHeader(x) => SignError::InvalidHeader(x),
                SignError::InvalidHeaderBuilder(x) => SignError::InvalidHeaderBuilder(x),
                SignError::Sign(x) => SignError::Sign(x),
                SignError::Payload(x) => match x {},
            })?;

        digest.update(b".");

        let payload = self
            .payload
            .provide_payload(&mut digest)
            .map_err(SignError::Payload)?;
        let signature = signer.sign_digest(digest).map_err(SignError::Sign)?;

        Ok(Signed {
            value: F::finalize(serialized_header, payload, signature.as_ref())
                .map_err(SignError::SerializeHeader)?,
        })
    }
}

/// Different kinds of errors that can occurr while parsing a JWS from it's
/// compact format.
#[derive(Debug, Error)]
pub enum ParseCompactError<P> {
    /// `crit` header field contained an unsupported name.
    #[error("encountered unsupported critical headers (crit header field)")]
    UnsupportedCriticalHeader,
    /// One of the parts was invalid UTF8
    #[error("one of the parts was an invalid UTF-8 byte sequence")]
    InvalidUtf8Encoding,
    /// One of the parts was an invalid Json string
    #[error("one of the parts was an invalid json string")]
    InvalidJson(#[source] serde_json::Error),
    /// The header of the JWS is invalid.
    #[error("invalid JWS header: {0}")]
    InvalidHeader(#[source] header::Error),
    /// Got a `Compact` with less or more than three elements.
    #[error("got compact representation that didn't have 3 parts")]
    InvalidLength,
    /// Failed to parse the payload.
    #[error(transparent)]
    Payload(P),
}

impl<F: Format, T> crate::sealed::Sealed for JsonWebSignature<F, T> {}

impl<T: FromRawPayload> DecodeFormat<Compact> for JsonWebSignature<Compact, T> {
    type Decoded<D> = Unverified<D>;
    type Error = ParseCompactError<T::Error>;

    fn decode(input: Compact) -> Result<Unverified<Self>, Self::Error> {
        if input.len() != 3 {
            return Err(ParseCompactError::InvalidLength);
        }

        let (header, raw_header) = {
            let raw = input.part(0).expect("`len()` is checked above to be 3");
            let json = String::from_utf8(raw.decode())
                .map_err(|_| ParseCompactError::InvalidUtf8Encoding)?;

            let header = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json)
                .map_err(ParseCompactError::InvalidJson)?;

            let header = JoseHeader::from_values(Some(header), None)
                .map_err(ParseCompactError::InvalidHeader)?;

            (header, json)
        };

        let (payload, raw_payload) = {
            let raw = input.part(1).expect("`len()` is checked above to be 3");
            let payload = PayloadKind::Standard(raw.clone());
            let payload = T::from_raw_payload(payload).map_err(ParseCompactError::Payload)?;
            (payload, raw.decode())
        };

        let signature = input.part(2).expect("`len()` is checked above to be 3");

        let raw_header = Base64UrlUnpadded::encode_string(raw_header.as_bytes());
        let raw_payload = Base64UrlUnpadded::encode_string(&raw_payload);

        let msg = alloc::format!("{}.{}", raw_header, raw_payload);

        Ok(Unverified {
            value: JsonWebSignature { header, payload },
            signature: signature.decode(),
            msg: msg.into_bytes(),
        })
    }
}

impl<T: FromRawPayload> DecodeFormat<JsonFlattened> for JsonWebSignature<JsonFlattened, T> {
    type Error = ();
    type Decoded<D> = Unverified<D>;

    fn decode(_input: JsonFlattened) -> Result<Self::Decoded<Self>, Self::Error> {
        todo!()
    }
}
