//! Symmetric cryptography for JWS and JWE

pub mod hmac;

use alloc::{string::String, vec::Vec};

use digest::InvalidLength;
use secrecy::{ExposeSecret, SecretBox};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
/// Instead, you should use [`HmacKey<H>`](crate::jwk::symmetric::hmac::HmacKey)
/// with the appropriate key size, for example
/// [`Hs512`](crate::jwk::symmetric::hmac::Hs512) and then, if needed, convert
/// it to a [`JsonWebKey`](crate::JsonWebKey) using
/// [`IntoJsonWebKey`](crate::jwk::IntoJsonWebKey).
///
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
#[derive(Debug, Clone, ZeroizeOnDrop, Zeroize)]
pub struct OctetSequence(pub(self) SecretBox<[u8]>);

impl OctetSequence {
    pub(crate) fn new(x: impl Into<Vec<u8>>) -> Self {
        let v: Vec<u8> = x.into();
        Self(SecretBox::new(v.into_boxed_slice()))
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
        self.0.expose_secret() == other.0.expose_secret()
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
/// An error that can occur when creating an [`HmacKey`](hmac::HmacKey) from an
/// [`OctetSequence`].
#[derive(Debug, thiserror_no_std::Error, PartialEq, Eq)]
pub enum FromOctetSequenceError {
    /// An invalid signing algorithm was used
    #[error(transparent)]
    InvalidSigningAlgorithm(#[from] InvalidSigningAlgorithmError),
    /// A key from which a signer should've been created had an invalid length
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}
