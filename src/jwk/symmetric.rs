//! Symmetric cryptography for JWS and JWE

pub mod hmac;

use alloc::string::String;

use digest::InvalidLength;
use serde::{de::Error, Deserialize, Deserializer, Serialize};

use crate::{base64_url::Base64UrlBytes, jws::InvalidSigningAlgorithmError};

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SymmetricJsonWebKey {
    /// `oct` <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence(OctetSequence),
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OctetSequence(pub(self) Base64UrlBytes);

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
            return Err(D::Error::custom("`kty` field is required to be \"oct\""));
        }

        Ok(Self(repr.k))
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
            k: &self.0,
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
