//! Implementation of JSON Web Signature (JWS) as defined in [RFC 7515]
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

use crate::{
    format::{Compact, IntoFormat},
    jwa::JsonWebSigningAlgorithm,
    sign::{Signable, Signer},
    Signed,
};

// FIXME: check section 5.3. (string comparison) and verify correctness
// FIXME: Appendix F: Detached Content

/// Everything that can be used as a payload for a [`JsonWebSignature`].
pub trait Payload {
    /// The type that contains the raw bytes.
    ///
    /// Exists to avoid allocations if possible.
    type Buf: AsRef<[u8]>;

    /// Turn `self` into it's raw byte representation that will
    /// be put into a [`JsonWebSignature`].
    fn as_bytes(&self) -> Self::Buf;
}

impl Payload for &[u8] {
    type Buf = Self;

    fn as_bytes(&self) -> Self::Buf {
        self
    }
}

impl Payload for Vec<u8> {
    type Buf = Vec<u8>;

    fn as_bytes(&self) -> Self::Buf {
        self.clone()
    }
}

/// Representation of a JSON Web Signature (JWS).
///
/// Consists of a header, that can have additional fields by using
/// the `H` argument (the type is passed to the [`JoseHeader`]).
///
/// The `T` type indicates the payload that will be put into this JWS.
///
/// When signing a [`JsonWebSignature`] using the [`Signable::sign`] method
/// the `signing_algorithm` field (and optionally the `key_id` field if present)
/// inside the header will be overwritten with the values from the new key
/// given as an argument to the `sign` method.
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
    additional: H,
}

impl<H> JsonWebSignatureBuilder<H> {
    /// Creates a new builder ready to be configured into a JWS.
    pub const fn new() -> JsonWebSignatureBuilder<()> {
        JsonWebSignatureBuilder { additional: () }
    }

    /// Configures the additional header parameters used for the final JWS.
    ///
    /// Note that this method takes `self` and not `&mut self` because
    /// it requires changing the generic parameter of a builder.
    pub fn additional_header<NH>(self, additional: NH) -> JsonWebSignatureBuilder<NH> {
        JsonWebSignatureBuilder { additional }
    }

    /// Creates the configures [`JsonWebSignature`] with the given payload.
    pub fn build<T>(self, payload: T) -> JsonWebSignature<T, H> {
        JsonWebSignature {
            header: JoseHeader::new_empty(JsonWebSigningAlgorithm::None, self.additional),
            payload,
        }
    }
}

impl JsonWebSignature<(), ()> {
    /// Returns a new builder to construct a JWS.
    pub const fn builder() -> JsonWebSignatureBuilder<()> {
        JsonWebSignatureBuilder { additional: () }
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

impl<T: Payload, H: Serialize> crate::sign::sealed::Sealed for JsonWebSignature<T, H> {}

impl<T: Payload, H: Serialize> Signable for JsonWebSignature<T, H> {
    type Error = ();

    fn sign<S: AsRef<[u8]>>(
        mut self,
        signer: &dyn Signer<S>,
    ) -> Result<Signed<Self, S>, Self::Error> {
        let mut input = Compact::with_capacity(2);

        self.header.signing_algorithm = signer.algorithm();
        self.header.key_id = signer.key_id();

        let header = serde_json::to_string(&self.header).unwrap();
        input.push(header.as_bytes());
        input.push(self.payload.as_bytes());

        let msg = input.to_string();

        let signature = signer.sign(msg.as_bytes()).unwrap();

        Ok(Signed {
            value: self,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn smoke() {
        let jws = JsonWebSignature::builder().build(String::from("abc"));

        impl Payload for String {
            type Buf = Vec<u8>;

            fn as_bytes(&self) -> Self::Buf {
                self.as_bytes().to_vec()
            }
        }

        struct NoneKey;

        impl Signer<&'static [u8]> for NoneKey {
            fn sign(&self, _: &[u8]) -> Result<&'static [u8], signature::Error> {
                Ok(&[])
            }

            fn algorithm(&self) -> JsonWebSigningAlgorithm {
                JsonWebSigningAlgorithm::None
            }
        }

        let c = jws.sign(&NoneKey).unwrap().encode::<Compact>();

        std::println!("{}", c);
    }
}

impl<T: Payload, H: Serialize> crate::format::sealed::Sealed for JsonWebSignature<T, H> {}

impl<T: Payload, H: Serialize> IntoFormat<Compact> for JsonWebSignature<T, H> {
    fn into_format(self) -> Compact {
        let mut input = Compact::with_capacity(2);

        // FIXME: can we unwrap here? is it 100% safe?
        let header = serde_json::to_string(&self.header).unwrap();
        input.push(header.as_bytes());
        input.push(self.payload.as_bytes());

        input
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
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `Url`
    pub jwk_set_url: Option<String>,
    /// The public key that corresponds to
    /// the key used to digitally sign the JWS.
    ///
    /// This is serialized as `jwk`.
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `JsonWebKey`
    pub json_web_key: Option<String>,
    /// Hint indicating which key was used to secure the JWS.
    ///
    /// This is serialized as `kid`.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    // FIXME: figure out what type to use instead of String
    pub key_id: Option<String>,
    /// A URI refering to a X.509 public key certificate or
    /// certificate chain corresponding to the used key.
    ///
    /// This is serialized as `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with `Url`
    pub x509_url: Option<String>,
    /// The public key certificate or certificate chain
    /// corresponding to the key used to sign the JWS.
    ///
    /// This is serialized as `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with certificate type
    pub x509_chain: Option<String>,
    /// Base64url-encoded SHA-1 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t`.
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with some `Base64String` type
    pub x509_fingerprint: Option<String>,
    /// Base64url-encoded SHA-256 digest of the DER
    /// encoding of the X.509 certificate
    ///
    /// This is serialized as `x5t#S256`.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    // FIXME: replace `String` with some `Base64String` type
    pub x509_fingerprint_sha256: Option<String>,
    /// This is used by the application to determine the type
    /// of the JWS.
    ///
    /// This is serialized as `typ`.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// This is used by the application to determine the type
    /// of content in the payload of this JWS.
    ///
    /// This is serialized as `cty`.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// List of critical extended headers.
    ///
    /// This is serialized as `crit`.
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
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
