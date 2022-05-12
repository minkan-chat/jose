//! Implementation of JSON Web Signature (JWS) as defined in [RFC 7515]
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::{format::Compact, jwa::JsonWebSigningAlgorithm, Signed};

// FIXME: check section 5.3. (string comparison) and verify correctness

/// Everything that can be used as a payload for a [`JsonWebSignature`].
pub trait Payload {
    /// The type that contains the raw bytes.
    ///
    /// Exists to avoid allocations if possible.
    type Buf: AsRef<[u8]>;

    /// Turn `self` into it's raw byte representation that will
    /// be put into a [`JsonWebSignature`].
    fn into_bytes(self) -> Self::Buf;
}

impl Payload for &[u8] {
    type Buf = Self;

    fn into_bytes(self) -> Self::Buf {
        self
    }
}

impl Payload for Vec<u8> {
    type Buf = Self;

    fn into_bytes(self) -> Self::Buf {
        self
    }
}

/// Representation of a JSON Web Signature (JWS).
///
/// Consists of a header, that can have additional fields by using
/// the `H` argument (the type is passed to the [`JoseHeader`]).
///
/// The `T` type indicates the payload that will be put into this JWS.
#[derive(Debug)]
pub struct JsonWebSignature<T, H = ()> {
    payload: T,
    header: H,
}

impl<T> JsonWebSignature<T, ()> {
    /// Create a new `JsonWebSignature` with the given payload.
    ///
    /// This method does not support to set the additional header (`H`).
    /// Use [`new_with_additional_header`](Self::new_with_additional_header) to
    /// create a JWS with additional header parameters.
    pub fn new(payload: T) -> Self {
        Self {
            header: (),
            payload,
        }
    }
}

impl<T, H> JsonWebSignature<T, H> {
    /// Create a new `JsonWebSignature` with the given payload and the
    /// additional header parameters.
    pub fn new_with_additional_header(payload: T, header: H) -> Self {
        Self { payload, header }
    }

    /// Sign this JWS with the given algorithm and key.
    pub fn sign<F>() -> Signed<Self, F> {
        todo!()
    }
}

impl<T, H> Signed<JsonWebSignature<T, H>, Compact> {
    ///
    pub fn encode() -> Self {
        todo!()
        // value.push(signature);
        // Self { value }
    }
}

// impl<T: Payload, H: Serialize> Encode<Compact> for JsonWebSignature<T, H> {
//     type Error = serde_json::Error;

//     fn encode(self) -> Result<Compact, Self::Error> {
//         let mut out = Compact::new();

//         let header = serde_json::to_string(&self.header)?;
//         out.push(header);
//         out.push(self.payload.into_bytes());

//         // FIXME: compute signature

//         Ok(out)
//     }
// }

/// (De-)serializable representation of a JOSE header
/// as defined by [section 4] in the JWS specification.
///
/// The generic argument `T` exists to support
/// additional ([public] or [private]) header parameters
/// that are not part of the specification.
/// By default the `T` is [`()`], so there are no
/// additional header parameters.
///
/// # Example
///
/// ```
/// # use jose::jws::JoseHeader;
/// # use jose::jwa::JsonWebSigningAlgorithm;
/// # use serde::{Serialize, Deserialize};
/// # fn main() {
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct MyPrivateHeaders {
///     foo: String,
/// }
///
/// type MyHeader = JoseHeader<MyPrivateHeaders>;
/// let header: MyHeader = serde_json::from_str(r#"{"alg": "none", "foo": "hello"}"#).unwrap();
///
/// assert_eq!(header.signing_algorithm, JsonWebSigningAlgorithm::None);
/// assert_eq!(header.additional.foo.as_str(), "hello");
/// # }
/// ```
///
/// [section 4]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
/// [public]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
/// [private]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
#[derive(Debug, Serialize, Deserialize)]
pub struct JoseHeader<T = ()> {
    /// Identifies the cryptographic algorithm
    /// used to secure the JWS.
    ///
    /// This is serialized as `alg`.
    #[serde(rename = "alg")]
    pub signing_algorithm: JsonWebSigningAlgorithm,
    /// Refers to a resource for a
    /// set of JSON-encoded public keys, one of which corresponds
    /// to the key used to digitally sign the JWS.
    ///
    /// This is serialized as `jku`.
    #[serde(rename = "jku")]
    // FIXME: replace `String` with `Url`
    pub jwk_set_url: Option<String>,
    /// The public key that corresponds to
    /// the key used to digitally sign the JWS.
    ///
    /// This is serialized as `jwk`.
    #[serde(rename = "jwk")]
    // FIXME: replace `String` with `JsonWebKey`
    pub json_web_key: Option<String>,
    /// Hint indicating which key was used to secure the JWS.
    ///
    /// This is serialized as `kid`.
    #[serde(rename = "kid")]
    // FIXME: figure out what type to use instead of String
    pub key_id: Option<String>,
    /// A URI refering to a X.509 public key certificate or
    /// certificate chain corresponding to the used key.
    ///
    /// This is serialized as `x5u`.
    #[serde(rename = "x5u")]
    // FIXME: replace `String` with `Url`
    pub x509_url: Option<String>,
    /// The public key certificate or certificate chain
    /// corresponding to the key used to sign the JWS.
    ///
    /// This is serialized as `x5c`.
    #[serde(rename = "x5c")]
    // FIXME: replace `String` with certificate type
    pub x509_chain: Option<String>,
    /// Base64url-encoded SHA-1 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t`.
    #[serde(rename = "x5t")]
    // FIXME: replace `String` with some `Base64String` type
    pub x509_fingerprint: Option<String>,
    /// Base64url-encoded SHA-256 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t#S256`.
    #[serde(rename = "x5t#S256")]
    // FIXME: replace `String` with some `Base64String` type
    pub x509_fingerprint_sha256: Option<String>,
    /// This is used by the application to determine the type
    /// of the JWS.
    ///
    /// This is serialized as `typ`.
    #[serde(rename = "typ")]
    pub media_type: Option<String>,
    /// This is used by the application to determine the type
    /// of content in the payload of this JWS.
    ///
    /// This is serialized as `cty`.
    #[serde(rename = "cty")]
    pub content_type: Option<String>,
    /// List of critical extended headers.
    ///
    /// This is serialized as `crit`.
    #[serde(rename = "crit")]
    // FIXME: figure out if we can replace Vec<String>
    // with a dedicated type
    // FIXME: check critical list when decoding JWS
    pub critical: Option<Vec<String>>,
    /// Additional (private or public) headers.
    ///
    /// This is attributed with `#[serde(flatten)]`.
    #[serde(flatten)]
    pub additional: T,
}

impl<T> JoseHeader<T> {
    /// Creates a new JoseHeader that has every optional field set to `None`.
    pub fn new_empty(alg: JsonWebSigningAlgorithm, additional: T) -> Self {
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
