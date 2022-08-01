//! Implementation of JSON Web Signature (JWS) as defined in [RFC 7515]
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::convert::Infallible;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use thiserror_no_std::Error;

use crate::{
    format::{Compact, FromFormat, IntoFormat, JsonFlattened},
    jwa::JsonWebSigningAlgorithm,
    sealed::Sealed,
    JsonWebKey,
};

mod sign;
mod verify;

#[doc(inline)]
pub use {sign::*, verify::*};

// FIXME: check section 5.3. (string comparison) and verify correctness
// FIXME: Appendix F: Detached Content
// FIXME: protected headers

/// Everything that can be used as a payload for a [`JsonWebSignature`].
pub trait Payload: Sized {
    /// The type that contains the raw bytes.
    type Buf: AsRef<[u8]>;

    /// The error that can occurr while converting
    /// this payload into it's byte representation.
    type IntoError;

    /// The error that can occurr while converting
    /// a raw byte sequence into this payload type.
    type FromError;

    /// Turn `self` into it's raw byte representation that will
    /// be put into a [`JsonWebSignature`].
    ///
    /// # Errors
    ///
    /// Returns an error if it failed to convert `self` into it's byte
    /// representation.
    fn into_bytes(self) -> Result<Self::Buf, Self::IntoError>;

    /// Convert a raw byte sequence into this payload.
    ///
    /// # Errors
    ///
    /// Returns an error if it failed to convert the byte representation to this
    /// type.
    fn from_bytes(input: Vec<u8>) -> Result<Self, Self::FromError>;
}

impl Payload for Vec<u8> {
    type Buf = Vec<u8>;
    type FromError = Infallible;
    type IntoError = Infallible;

    fn into_bytes(self) -> Result<Self::Buf, Self::IntoError> {
        Ok(self)
    }

    fn from_bytes(input: Vec<u8>) -> Result<Self, Self::FromError> {
        Ok(input)
    }
}

impl Payload for String {
    type Buf = Vec<u8>;
    type FromError = alloc::string::FromUtf8Error;
    type IntoError = Infallible;

    fn into_bytes(self) -> Result<Self::Buf, Self::IntoError> {
        Ok(self.into_bytes())
    }

    fn from_bytes(input: Vec<u8>) -> Result<Self, Self::FromError> {
        String::from_utf8(input)
    }
}

/// Different kinds of errors that can occurr while signing a JWS.
#[derive(Debug, Error)]
pub enum SignError<P> {
    /// Failed to serialize the [`JoseHeader`].
    #[error("failed to serialize header: {0}")]
    SerializeHeader(#[source] serde_json::Error),
    /// The underlying signing operation of the given signer failed.
    #[error(transparent)]
    Sign(signature::Error),
    /// Failed to convert payload into it's raw byte representation.
    #[error(transparent)]
    Payload(P),
}

/// Representation of a JSON Web Signature (JWS).
///
/// Consists of a header, that can have additional fields by using
/// the `H` argument (the type is passed to the [`JoseHeader`]).
///
/// The `T` type indicates the payload that will be put into this JWS.
///
/// When signing a [`JsonWebSignature`] using the
/// [`sign`](JsonWebSignature::sign) method the `signing_algorithm` field (and
/// optionally the `key_id` field if present) inside the header will be
/// overwritten with the values from the new key given as an argument to the
/// `sign` method.
#[derive(Debug)]
pub struct JsonWebSignature<T, H = ()> {
    header: JoseHeader<H>,
    payload: T,
}

impl<T> JsonWebSignature<T, ()> {
    /// Creates a new JsonWebSignature with just the given payload
    /// and no additional header parameters.
    ///
    /// To add additional header parameters use the
    /// [`new_with_header`](Self::new_with_header) method.
    pub const fn new(payload: T) -> Self {
        Self {
            header: JoseHeader::new_empty(JsonWebSigningAlgorithm::None, ()),
            payload,
        }
    }
}

/// The builder for constructing a [`JsonWebSignature`].
///
/// This is mainly used for specifiying specific header parameters.
/// If you only require the default header values, use the
/// [`JsonWebSignature::new`] method.
#[derive(Debug, Clone)]
pub struct JsonWebSignatureBuilder<H> {
    header: JoseHeader<H>,
}

impl JsonWebSignatureBuilder<()> {
    /// Creates a new builder ready to be configured into a JWS.
    pub const fn new() -> JsonWebSignatureBuilder<()> {
        JsonWebSignatureBuilder {
            header: JoseHeader::new_empty(JsonWebSigningAlgorithm::None, ()),
        }
    }
}

impl<H> JsonWebSignatureBuilder<H> {
    /// Configures the additional header parameters used for the final JWS.
    ///
    /// Note that this method takes `self` and not `&mut self` because
    /// it requires changing the generic parameter of a builder.
    pub fn additional_header<NH>(self, additional: NH) -> JsonWebSignatureBuilder<NH> {
        JsonWebSignatureBuilder {
            header: JoseHeader {
                signing_algorithm: self.header.signing_algorithm,
                jwk_set_url: self.header.jwk_set_url,
                json_web_key: self.header.json_web_key,
                key_id: self.header.key_id,
                x509_url: self.header.x509_url,
                x509_chain: self.header.x509_chain,
                x509_fingerprint: self.header.x509_fingerprint,
                x509_fingerprint_sha256: self.header.x509_fingerprint_sha256,
                media_type: self.header.media_type,
                content_type: self.header.content_type,
                critical: self.header.critical,
                additional,
            },
        }
    }

    /// Sets the list of critical header parameters inside this JWS header.
    ///
    /// Defined in [section 4.1.11] of the JWS RFC.
    ///
    /// [section 4.1.11]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11
    pub fn critical(mut self, crit: Vec<String>) -> Self {
        self.header.critical = Some(crit);
        self
    }

    /// Sets the JWK Set url parameter of the JWS header.
    ///
    /// Defined in [section 4.1.2] of the JWS RFC.
    /// Note that it's your responsibility to pass a valid URI as defined by the
    /// RFC. Providing an invalid URI will lead to an spec-incompatible JWS.
    ///
    ///
    /// [section 4.1.2]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2
    pub fn jwk_set_url(mut self, url: String) -> Self {
        self.header.jwk_set_url = Some(url);
        self
    }

    /// Sets the media type parameter of the JWS header to the given string.
    ///
    /// Defined in [section 4.1.9] of the JWS RFC.
    /// Note that it's your responsibility to supply a valid media type as
    /// there's no checking of the validity of the supplied type.
    ///
    /// [section 4.1.9]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
    pub fn media_type(mut self, typ: String) -> Self {
        self.header.media_type = Some(typ);
        self
    }

    /// Sets the content type parameter of the JWS header to the given string.
    ///
    /// Defined in [section 4.1.10] of the JWS RFC.
    /// Note that it's your responsibility to supply a valid media type as
    /// there's no checking of the validity of the supplied type.
    ///
    /// [section 4.1.10]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10
    pub fn content_type(mut self, typ: String) -> Self {
        self.header.content_type = Some(typ);
        self
    }

    /// Creates the configures [`JsonWebSignature`] with the given payload.
    pub fn build<T>(self, payload: T) -> JsonWebSignature<T, H> {
        JsonWebSignature {
            header: self.header,
            payload,
        }
    }
}

impl JsonWebSignature<(), ()> {
    /// Returns a new builder to construct a JWS.
    pub const fn builder() -> JsonWebSignatureBuilder<()> {
        JsonWebSignatureBuilder::new()
    }
}

impl<T, H> JsonWebSignature<T, H> {
    /// Creates a new JsonWebSignature with the given payload and the given
    /// additional header parameters.
    pub const fn new_with_header(payload: T, additional: H) -> Self {
        Self {
            header: JoseHeader::new_empty(JsonWebSigningAlgorithm::None, additional),
            payload,
        }
    }
}

/// Different kinds of errors that can occurr while parsing a JWS from it's
/// compact format.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ParseCompactError<P> {
    /// `crit` header field contained an unsupported name.
    #[error("encountered unsupported critical headers (crit header field)")]
    UnsupportedCriticalHeader,
    /// One of the parts was invalid UTF8
    #[error("one of the parts was an invalid UTF-8 byte sequence")]
    InvalidUtf8Encoding,
    /// One of the parts was an invalid Json string
    #[error("one of the parts was an invalid json string")]
    InvalidJson,
    /// Got a `Compact` with less or more than three elements.
    #[error("got compact representation that didn't have 3 parts")]
    InvalidLength,
    /// Failed to parse the payload.
    #[error(transparent)]
    Payload(P),
}

impl<T: Payload, H: DeserializeOwned> FromFormat<Compact> for JsonWebSignature<T, H> {
    type Error = ParseCompactError<T::FromError>;

    fn from_format(input: Compact) -> Result<Unverified<Self>, Self::Error> {
        if input.len() != 3 {
            return Err(ParseCompactError::InvalidLength);
        }

        let (header, raw_header) = {
            let raw = input.part(0).expect("`len()` is checked above to be 3");
            let json =
                String::from_utf8(raw).map_err(|_| ParseCompactError::InvalidUtf8Encoding)?;
            let header = serde_json::from_str::<JoseHeader<H>>(&json)
                .map_err(|_| ParseCompactError::InvalidJson)?;
            (header, json)
        };

        // currently no extension is supported, so deny if any entry is in `crit` list
        if header.critical.as_ref().map_or(false, |l| !l.is_empty()) {
            return Err(ParseCompactError::UnsupportedCriticalHeader);
        }

        let (payload, raw_payload) = {
            let raw = input.part(1).expect("`len()` is checked above to be 3");
            let payload = T::from_bytes(raw.clone()).map_err(ParseCompactError::Payload)?;
            (payload, raw)
        };

        let signature = input.part(2).expect("`len()` is checked above to be 3");

        let raw_header = Base64UrlUnpadded::encode_string(raw_header.as_bytes());
        let raw_payload = Base64UrlUnpadded::encode_string(&raw_payload);

        let msg = alloc::format!("{}.{}", raw_header, raw_payload);

        Ok(Unverified {
            value: JsonWebSignature { header, payload },
            signature,
            msg: msg.into_bytes(),
        })
    }
}

/// Internal use.
///
/// Cached value of the header and payload both
/// stores as Base64Url strings.
//#[doc(hidden)]
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct JsonWebSignatureValue {
    header: String,
    payload: String,
}

impl Sealed for JsonWebSignatureValue {}
impl<T, H> Sealed for JsonWebSignature<T, H> {}

impl<T: Payload, H: Serialize> JsonWebSignature<T, H>
where
    T: Payload,
    H: Serialize,
{
    /// Create a signature over the contents of this [`JsonWebSignature`] with
    /// the given [`Signer`]
    ///
    /// # Errors
    ///
    ///  This method returns an error if the serialization of the header `H`
    /// fails or if the [`Signer`] returns an error.
    pub fn sign<S: AsRef<[u8]>, D: digest::Update>(
        mut self,
        signer: &mut dyn Signer<S, Digest = D>,
    ) -> Result<Signed<S>, SignError<T::IntoError>> {
        self.header.signing_algorithm = signer.algorithm();
        self.header.key_id = signer.key_id().map(|s| s.to_string());

        let header = serde_json::to_value(&self.header).map_err(SignError::SerializeHeader)?;
        let header = Base64UrlUnpadded::encode_string(header.to_string().as_bytes());

        let payload = self.payload.into_bytes().map_err(SignError::Payload)?;
        let payload = Base64UrlUnpadded::encode_string(payload.as_ref());

        let mut digest = signer.new_digest();
        digest.update(header.as_bytes());
        digest.update(b".");
        digest.update(payload.as_bytes());
        let signature = signer.finalize(digest).map_err(SignError::Sign)?;

        Ok(Signed {
            value: JsonWebSignatureValue { header, payload },
            signature,
        })
    }
}

impl IntoFormat<Compact> for JsonWebSignatureValue {
    fn into_format(self) -> Compact {
        let mut fmt = Compact::with_capacity(3);
        fmt.push_base64url(self.header);
        fmt.push_base64url(self.payload);
        fmt
    }
}

impl IntoFormat<JsonFlattened> for JsonWebSignatureValue {
    fn into_format(self) -> JsonFlattened {
        let mut value = Value::Object(serde_json::Map::new());

        value["protected"] = Value::String(self.header);
        value["payload"] = Value::String(self.payload);

        JsonFlattened { value }
    }
}

/// (De-)serializable representation of a JOSE header
/// as defined by [section 4] in the JWS specification.
///
/// The generic argument `T` exists to support
/// additional ([public] or [private]) header parameters
/// that are not part of the specification.
/// By default the `T` is [`()`], so there are no
/// additional header parameters.
///
/// [section 4]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
/// [public]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
/// [private]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoseHeader<T = ()> {
    /// Identifies the cryptographic algorithm
    /// used to secure the JWS.
    ///
    /// This is serialized as `alg`.
    #[serde(rename = "alg")]
    signing_algorithm: JsonWebSigningAlgorithm,
    /// Refers to a resource for a
    /// set of JSON-encoded public keys, one of which corresponds
    /// to the key used to digitally sign the JWS.
    ///
    /// This is serialized as `jku`.
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `Url`
    jwk_set_url: Option<String>,
    /// The public key that corresponds to
    /// the key used to digitally sign the JWS.
    ///
    /// This is serialized as `jwk`.
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `JsonWebKey`
    json_web_key: Option<JsonWebKey>,
    /// Hint indicating which key was used to secure the JWS.
    ///
    /// This is serialized as `kid`.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    // FIXME: figure out what type to use instead of String
    key_id: Option<String>,
    /// A URI refering to a X.509 public key certificate or
    /// certificate chain corresponding to the used key.
    ///
    /// This is serialized as `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `Url`
    x509_url: Option<String>,
    /// The public key certificate or certificate chain
    /// corresponding to the key used to sign the JWS.
    ///
    /// This is serialized as `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with certificate type
    x509_chain: Option<String>,
    /// Base64url-encoded SHA-1 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t`.
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with some `Base64String` type
    x509_fingerprint: Option<String>,
    /// Base64url-encoded SHA-256 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t#S256`.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with some `Base64String` type
    x509_fingerprint_sha256: Option<String>,
    /// This is used by the application to determine the type
    /// of the JWS.
    ///
    /// This is serialized as `typ`.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    /// This is used by the application to determine the type
    /// of content in the payload of this JWS.
    ///
    /// This is serialized as `cty`.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    /// List of critical extended headers.
    ///
    /// This is serialized as `crit`.
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    critical: Option<Vec<String>>,
    /// Additional (private or public) headers.
    ///
    /// This is attributed with `#[serde(flatten)]`.
    #[serde(flatten)]
    additional: T,
}

impl<T> JoseHeader<T> {
    /// Creates a new JoseHeader that has every optional field set to `None`.
    pub const fn new_empty(alg: JsonWebSigningAlgorithm, additional: T) -> Self {
        Self {
            signing_algorithm: alg,
            jwk_set_url: None,
            json_web_key: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_fingerprint: None,
            x509_fingerprint_sha256: None,
            media_type: None,
            content_type: None,
            critical: None,
            additional,
        }
    }
}
