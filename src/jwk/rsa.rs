use alloc::{boxed::Box, format, vec};

use base64ct::{Base64, Encoding};
use rsa::BigUint;
use serde::{de::Error, Deserialize, Deserializer};

use crate::{jwa::JsonWebSigningAlgorithm, sign::Signer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaKey {
    Public(RsaPublicKey),
    Private(Box<RsaPrivateKey>),
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey(rsa::RsaPublicKey);

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPrivateKey(rsa::RsaPrivateKey);

impl<'de> Deserialize<'de> for RsaPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr<'a> {
            kty: &'a str,
            /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1>
            n: Base64UrlUInt,
            /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2>
            e: Base64UrlUInt,
            /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1>
            d: Base64UrlUInt,
            // FIXME: validate to ensure tokens are spec compliant
            #[serde(flatten)]
            _extra: Option<Extra>,
        }

        // see <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2>
        // we dont use these extra parameters but they still want to make sure that they
        // are spec complaint
        #[derive(Deserialize)]
        struct Extra {
            _p: Base64UrlUInt,
            _q: Base64UrlUInt,
            _dp: Base64UrlUInt,
            _dq: Base64UrlUInt,
            _qi: Base64UrlUInt,
            // FIXME: verify `oth` parameter
        }

        let v = <Repr<'_> as Deserialize>::deserialize(deserializer)?;
        if v.kty != "RSA" {
            return Err(<D as Deserializer>::Error::custom(format!(
                "invalid key type: `{}`, expected `RSA`",
                v.kty
            )));
        }
        Ok(Self(rsa::RsaPrivateKey::from_components(
            v.n.0,
            v.e.0,
            v.d.0,
            vec![], // FIXME: is this right?
        )))
    }
}

/// The big endian representation of a [`BigUint`] encoded in base64 urlsafe
/// without padding
#[repr(transparent)]
struct Base64UrlUInt(BigUint);

impl<'de> Deserialize<'de> for Base64UrlUInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let big_endian = Base64::decode_vec(
            <&str as Deserialize>::deserialize(deserializer)
                .map_err(<D::Error as Error>::custom)?,
        )
        .map_err(<D::Error as Error>::custom)?;

        Ok(Self(BigUint::from_bytes_be(&big_endian)))
    }
}
