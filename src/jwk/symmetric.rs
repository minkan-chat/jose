//! Symmetric cryptography for JWS and JWE

use alloc::string::String;

use secrecy::{ExposeSecret, SecretBox};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::thumbprint::{self, Thumbprint};
use crate::{base64_url::Base64UrlBytes, jws::InvalidSigningAlgorithmError};

/// Symmetric Keys
///
/// Symmetric keys only have a secret value, therefore, they MUST only be used
/// in a protected environment.
/// For example, with a symmetric key, checking the validity of a
/// [`JsonWebSignature`](crate::JsonWebSignature) cannot be done on the client
/// side, because it leaks the key and the client can then create own
/// signatures.
///
/// See <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum SymmetricJsonWebKey {
    /// `oct` <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence(OctetSequence),
}

impl crate::sealed::Sealed for SymmetricJsonWebKey {}
impl Thumbprint for SymmetricJsonWebKey {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            SymmetricJsonWebKey::OctetSequence(key) => key.thumbprint_prehashed(),
        }
    }
}

/// [`OctetSequence`] is the simplest and only available
/// [`SymmetricJsonWebKey`].
///
/// However, because its length is not defined, it cannot be generated directly.
/// Instead, you should use [`HmacKey<H>`](crate::crypto::hmac::Key)
/// with the appropriate key size, for example
/// [`Hs512`](crate::crypto::hmac::Hs512) and then, if needed, convert
/// it to a [`JsonWebKey`](crate::JsonWebKey) using
/// [`IntoJsonWebKey`](crate::jwk::IntoJsonWebKey).
///
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
#[derive(Debug, Clone, Zeroize)]
pub struct OctetSequence(SecretBox<[u8]>);

impl OctetSequence {
    pub(crate) fn new(x: SecretBox<[u8]>) -> Self {
        Self(x)
    }

    /// Returns the bytes of this octet sequence.
    pub(crate) fn bytes(&self) -> &SecretBox<[u8]> {
        &self.0
    }

    /// Returns the bytes of this octet sequence.
    pub(crate) fn into_bytes(self) -> SecretBox<[u8]> {
        self.0
    }

    /// Returns the number of bytes that are in this octet sequence.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Returns `true` if this octet sequence has a length of zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for OctetSequence {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.expose_secret().ct_eq(other.0.expose_secret()))
    }
}
impl Eq for OctetSequence {}

impl crate::sealed::Sealed for OctetSequence {}
impl Thumbprint for OctetSequence {
    fn thumbprint_prehashed(&self) -> String {
        thumbprint::serialize_key_thumbprint(self)
    }
}

impl From<SymmetricJsonWebKey> for super::JsonWebKeyType {
    fn from(x: SymmetricJsonWebKey) -> Self {
        super::JsonWebKeyType::Symmetric(x)
    }
}

impl From<OctetSequence> for super::JsonWebKeyType {
    fn from(x: OctetSequence) -> Self {
        super::JsonWebKeyType::Symmetric(SymmetricJsonWebKey::OctetSequence(x))
    }
}

impl<'de> Deserialize<'de> for OctetSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            kty: String,
            k: Base64UrlBytes,
        }

        let repr = Repr::deserialize(deserializer)?;
        if repr.kty != "oct" {
            return Err(D::Error::custom("`kty` field is required to be `oct`"));
        }
        Ok(Self(SecretBox::new(repr.k.0.into_boxed_slice())))
    }
}

impl Serialize for OctetSequence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Repr<'a> {
            kty: &'static str,
            k: &'a Base64UrlBytes,
        }
        Repr {
            kty: "oct",
            k: &Base64UrlBytes(self.0.expose_secret().to_vec()),
        }
        .serialize(serializer)
    }
}

/// An error that can occur when creating an
/// [`HmacKey`](crate::crypto::hmac::Key) from an [`OctetSequence`].
#[derive(Debug, thiserror::Error)]
pub enum FromOctetSequenceError {
    /// An invalid signing algorithm was used
    #[error(transparent)]
    InvalidSigningAlgorithm(#[from] InvalidSigningAlgorithmError),

    /// A key from which a signer should've been created had an invalid length
    #[error("the length of the is invalid")]
    InvalidLength,

    /// Crypto backend threw an unknown error.
    #[error("the crypto backend failed")]
    Crypto(
        #[from]
        #[source]
        crate::crypto::Error,
    ),
}
