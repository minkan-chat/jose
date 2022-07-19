//! Symmetric cryptography for JWS and JWE

pub mod hmac;

use alloc::{string::String, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use digest::InvalidLength;
use serde::{de::Error, Deserialize, Serialize};

use crate::{base64_url::Base64UrlBytes, jws::InvalidSigningAlgorithmError};

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum SymmetricJsonWebKey {
    /// `oct` <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence(OctetSequence),
}

impl Serialize for SymmetricJsonWebKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SymmetricJsonWebKey::OctetSequence(bytes) => {
                #[derive(Serialize)]
                struct Repr {
                    kty: &'static str,
                    k: String,
                }

                let encoded = Base64UrlUnpadded::encode_string(&bytes.0);

                Repr {
                    kty: "oct",
                    k: encoded,
                }
                .serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for SymmetricJsonWebKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct OctetRepr {
            kty: String,
            k: Base64UrlBytes,
        }

        let repr = OctetRepr::deserialize(deserializer)?;

        if repr.kty != "oct" {
            return Err(D::Error::custom("`kty` field is required to be \"oct\""));
        }

        Ok(SymmetricJsonWebKey::OctetSequence(OctetSequence(repr.k.0)))
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OctetSequence(pub(self) Vec<u8>);

/// An error that can occur when creating an [`HmacKey`](hmac::HmacKey) from an
/// [`OctetSequence`].
#[derive(Debug, thiserror_no_std::Error)]
pub enum FromOctetSequenceError {
    /// An invalid signing algorithm was used
    #[error(transparent)]
    InvalidSigningAlgorithm(#[from] InvalidSigningAlgorithmError),
    /// A key from which a signer should've been created had an invalid length
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}
