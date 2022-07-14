//! Symmetric cryptography for JWS and JWE
use alloc::{string::String, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error, Deserialize, Serialize};

use crate::base64_url::Base64UrlBytes;

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

use digest::{InvalidLength, Mac, Output};
use hmac::Hmac;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    jwa::{Hmac as Hs, JsonWebSigningAlgorithm},
    jws::{FromKey, InvalidSigningAlgorithmError, Signer},
};

/// An error that can occur then creating [`Hs256Signer`], [`Hs384Signer`] or
/// [`Hs512Signer`] from an [`OctetSequence`]
#[derive(Debug, thiserror_no_std::Error)]
pub enum FromOctetSequenceError {
    /// An invalid signing algorithm was used
    #[error(transparent)]
    InvalidSigningAlgorithm(#[from] InvalidSigningAlgorithmError),
    /// A key from which a signer should've been created had an invalid length
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}



hs_signer!(
    /// A [`Signer`] using [`Hs256`](Hs::Hs256) with a [`OctetSequence`]
    Hs256Signer,
    Sha256,
    Hs::Hs256,
    Hs::Hs256
);
hs_signer!(
    /// A [`Signer`] using [`Hs384`](Hs::Hs384) with a [`OctetSequence`]
    Hs384Signer,
    Sha384,
    Hs::Hs384,
    Hs::Hs384
);
hs_signer!(
    /// A [`Signer`] using [`Hs512`](Hs::Hs512) with a [`OctetSequence`]
    Hs512Signer,
    Sha512,
    Hs::Hs512,
    Hs::Hs512
);
