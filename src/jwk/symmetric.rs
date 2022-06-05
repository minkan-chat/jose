use alloc::{string::String, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error, Deserialize, Serialize};

use crate::base64_url::Base64UrlBytes;

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug)]
pub enum SymmetricJsonWebKey {
    /// `oct` <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence(OctetSequence),
}

impl serde::Serialize for SymmetricJsonWebKey {
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
#[derive(Debug)]
pub struct OctetSequence(Vec<u8>);
