//! Implementation of JSON Web Signature (JWS) as defined in [RFC 7515]
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>

use alloc::{format, string::String, vec, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use thiserror_no_std::Error;

use crate::{
    format::{Compact, DecodeFormat, Format, JsonFlattened, JsonGeneral, JsonGeneralSignature},
    header, Base64UrlString, JoseHeader,
};

mod builder;
mod sign;
mod verify;

#[doc(inline)]
pub use {builder::*, sign::*, verify::*};

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
    /// The number of headers in the JWS does not match the number of
    /// [`Signer`]s.
    ///
    /// This error is only possible when using the [`JsonGeneral`] format.
    #[error("the number of headers does not match the number of signers")]
    HeaderCountMismatch,
    /// Failed to serialize the [`JoseHeader`](crate::header::JoseHeader).
    #[error("failed to serialize header: {0}")]
    SerializeHeader(#[source] serde_json::Error),
    /// The `protected` part of the header was empty, which is disallowed in the
    /// compact format.
    #[error("the protected header was empty on a compact JWS")]
    EmptyProtectedHeader,
    /// The header of the JWS is invalid.
    #[error("invalid JWS header: {0}")]
    InvalidHeader(#[source] header::Error),
    /// The underlying signing operation of the given signer failed.
    #[error(transparent)]
    Sign(signature::Error),
    /// Failed to convert payload into it's raw byte representation.
    #[error(transparent)]
    Payload(P),
}

/// Represents a JSON Web Signature (JWS) as defined in [RFC 7515].
///
/// The JWS is a format for representing digitally signed or MACed (Message
/// Authentication Code) content using JSON. The JSON representation is used
/// to convey the payload, the signature, and optionally additional meta-data
/// about the payload and signature.
///
/// The [`JsonWebSignature`] struct has two type parameters:
///
/// * `F`: The format of the JWS. This can be either [`Compact`] or
///   [`JsonFlattened`].
/// * `T`: The type of the payload. This can be any type that implements the
///   [`ProvidePayload`] trait and also the [`FromRawPayload`] trait.
///
/// [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>
#[derive(Debug)]
pub struct JsonWebSignature<F: Format, T> {
    header: F::JwsHeader,
    payload: T,
}

impl<F: Format> JsonWebSignature<F, ()> {
    /// Constructs a [`JsonWebSignatureBuilder`].
    pub fn builder() -> JsonWebSignatureBuilder<F> {
        JsonWebSignatureBuilder::new()
    }
}

impl<F: Format, T> JsonWebSignature<F, T> {
    pub(crate) fn new(header: F::JwsHeader, payload: T) -> Self {
        Self { header, payload }
    }

    /// Returns a reference to the payload of this JWS.
    pub fn payload(&self) -> &T {
        &self.payload
    }
}

impl<T> JsonWebSignature<Compact, T> {
    /// Returns a reference to the [`JoseHeader`](crate::header::JoseHeader) of
    /// this JWS.
    pub fn header(&self) -> &JoseHeader<Compact, header::Jws> {
        &self.header
    }
}

impl<T> JsonWebSignature<JsonFlattened, T> {
    /// Returns a reference to the [`JoseHeader`](crate::header::JoseHeader) of
    /// this JWS.
    pub fn header(&self) -> &JoseHeader<JsonFlattened, header::Jws> {
        &self.header
    }
}

impl<T> JsonWebSignature<JsonGeneral, T> {
    /// Returns a reference to the list of [`JoseHeader`] of this JWS.
    pub fn header(&self) -> &Vec<JoseHeader<JsonGeneral, header::Jws>> {
        &self.header
    }
}

impl<F: Format, T: ProvidePayload> JsonWebSignature<F, T> {
    /// Signs this [`JsonWebSignature`] using the given `signer`.
    ///
    /// When signing the JWS, some fields of the header of this JWS may be
    /// updated. For example, the `alg` header parameter will be updated to
    /// reflect the algorithm used to sign the JWS, and the `kid` header
    /// parameter may be updated using the value from the given [`Signer`].
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
        F::update_header(&mut self.header, signer);

        let mut digest = signer.new_digest();
        let serialized_header =
            F::provide_header(self.header, &mut digest).map_err(|x| match x {
                SignError::HeaderCountMismatch => SignError::HeaderCountMismatch,
                SignError::SerializeHeader(x) => SignError::SerializeHeader(x),
                SignError::InvalidHeader(x) => SignError::InvalidHeader(x),
                SignError::EmptyProtectedHeader => SignError::EmptyProtectedHeader,
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

impl<T: ProvidePayload> JsonWebSignature<JsonGeneral, T> {
    /// Signs this JWS using multiple signers.
    ///
    /// This is only supported when the JWS is in the [`JsonGeneral`] format.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of the given iterator of signers does
    /// not match the number of headers in this JWS.
    /// Otherwise, this method may return the same errors as the normal sign operation.
    pub fn sign_many<'s, S: AsRef<[u8]> + 's, D: digest::Update + 's>(
        mut self,
        signers: impl IntoIterator<Item = &'s mut dyn Signer<S, Digest = D>>,
    ) -> Result<Signed<JsonGeneral>, SignError<T::Error>> {
        if self.header.is_empty() {
            // this is unreachable right now, but we don't want to panic, so just return a
            // kind of matching error
            return Err(SignError::HeaderCountMismatch);
        }

        let signers = signers.into_iter().collect::<Vec<_>>();

        if signers.len() != self.header.len() {
            return Err(SignError::HeaderCountMismatch);
        }

        let mut final_payload = None;
        let mut signatures = vec![];

        for (mut hdr, signer) in self.header.into_iter().zip(signers) {
            hdr.overwrite_alg_and_key_id(signer.algorithm(), signer.key_id());

            let mut digest = signer.new_digest();

            let serialized_hdr = {
                let (protected, unprotected) =
                    hdr.into_values().map_err(SignError::InvalidHeader)?;

                let protected = match protected {
                    Some(hdr) => {
                        let json =
                            serde_json::to_string(&hdr).map_err(SignError::SerializeHeader)?;

                        let encoded = Base64UrlString::encode(json);
                        digest.update(encoded.as_bytes());
                        Some(encoded)
                    }
                    None => None,
                };

                (protected, unprotected)
            };

            digest.update(b".");

            let payload = self
                .payload
                .provide_payload(&mut digest)
                .map_err(SignError::Payload)?;

            if final_payload.is_none() {
                final_payload = Some(payload);
            }

            let signature = signer.sign_digest(digest).map_err(SignError::Sign)?;

            signatures.push(JsonGeneralSignature {
                protected: serialized_hdr.0,
                header: serialized_hdr.1,
                signature: Base64UrlString::encode(signature.as_ref()),
            });
        }

        let final_payload = final_payload.expect("payload must be set");
        let PayloadKind::Standard(payload) = final_payload;

        Ok(Signed {
            value: JsonGeneral {
                payload,
                signatures,
            },
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

            (header, raw)
        };

        let (payload, raw_payload) = {
            let raw = input.part(1).expect("`len()` is checked above to be 3");
            let payload = PayloadKind::Standard(raw.clone());
            let payload = T::from_raw_payload(payload).map_err(ParseCompactError::Payload)?;
            (payload, raw.decode())
        };

        let signature = input.part(2).expect("`len()` is checked above to be 3");

        let raw_payload = Base64UrlUnpadded::encode_string(&raw_payload);

        let msg = format!("{}.{}", raw_header, raw_payload);

        Ok(Unverified {
            value: JsonWebSignature { header, payload },
            signature: signature.decode(),
            msg: msg.into_bytes(),
        })
    }
}

fn parse_json_header<F: Format, E>(
    protected: Option<Base64UrlString>,
    header: Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<JoseHeader<F, header::Jws>, ParseJsonError<E>> {
    let protected = match protected {
        Some(encoded) => {
            let json = String::from_utf8(encoded.decode())
                .map_err(|_| ParseJsonError::InvalidUtf8Encoding)?;

            let values = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json)
                .map_err(ParseJsonError::InvalidJson)?;
            Some(values)
        }
        None => None,
    };

    JoseHeader::from_values(protected, header).map_err(ParseJsonError::InvalidHeader)
}

/// Different kinds of errors that can occurr while parsing a JWS from it's
/// JSON, general or flattened, format.
#[derive(Debug, Error)]
pub enum ParseJsonError<P> {
    /// The `signatures` array was empty.
    ///
    /// This error can only happen when decoding the [`JsonGeneral`] format.
    #[error("the signatures array was empty")]
    EmptySignatures,
    /// The header of the JWS is invalid.
    #[error("invalid JWS header: {0}")]
    InvalidHeader(#[source] header::Error),
    /// The protected header or signature contained invalid UTF-8
    #[error("protected header or signature contained invalid UTF-8")]
    InvalidUtf8Encoding,
    /// The protected header contained invalid JSON
    #[error("protected header contained invalid JSON")]
    InvalidJson(#[source] serde_json::Error),
    /// Failed to parse the payload.
    #[error(transparent)]
    Payload(P),
}

impl<T: FromRawPayload> DecodeFormat<JsonFlattened> for JsonWebSignature<JsonFlattened, T> {
    type Decoded<D> = Unverified<D>;
    type Error = ParseJsonError<T::Error>;

    fn decode(
        JsonFlattened {
            payload,
            protected,
            header,
            signature,
        }: JsonFlattened,
    ) -> Result<Self::Decoded<Self>, Self::Error> {
        let msg = match protected {
            Some(ref protected) => format!("{}.{}", protected, payload),
            None => format!(".{}", payload),
        };

        let header = parse_json_header(protected, header)?;

        let payload = {
            let payload_kind = PayloadKind::Standard(payload);
            T::from_raw_payload(payload_kind).map_err(ParseJsonError::Payload)?
        };

        Ok(Unverified {
            value: JsonWebSignature { header, payload },
            signature: signature.decode(),
            msg: msg.into_bytes(),
        })
    }
}

impl<T: FromRawPayload> DecodeFormat<JsonGeneral> for JsonWebSignature<JsonGeneral, T> {
    type Decoded<D> = ManyUnverified<D>;
    type Error = ParseJsonError<T::Error>;

    fn decode(
        JsonGeneral {
            payload,
            signatures,
        }: JsonGeneral,
    ) -> Result<Self::Decoded<Self>, Self::Error> {
        if signatures.is_empty() {
            return Err(ParseJsonError::EmptySignatures);
        }

        let mut headers = vec![];
        let mut unverified_signatures = vec![];

        for sig in signatures {
            let msg = match sig.protected {
                Some(ref protected) => format!("{}.{}", protected, payload),
                None => format!(".{}", payload),
            };

            let header = parse_json_header(sig.protected, sig.header)?;

            headers.push(header);
            unverified_signatures.push((msg.into_bytes(), sig.signature.decode()));
        }

        let payload = {
            let payload_kind = PayloadKind::Standard(payload);
            T::from_raw_payload(payload_kind).map_err(ParseJsonError::Payload)?
        };

        Ok(ManyUnverified {
            value: JsonWebSignature {
                header: headers,
                payload,
            },
            signatures: unverified_signatures,
        })
    }
}
