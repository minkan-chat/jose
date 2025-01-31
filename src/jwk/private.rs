use alloc::{boxed::Box, string::String};

use serde::{Deserialize, Serialize};

use super::{ec::EcPrivate, okp::OkpPrivate, rsa::RsaPrivateKey, Thumbprint};

/// The `private` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum Private {
    /// The private part of a Rsa key
    Rsa(Box<RsaPrivateKey>),
    /// The private part of an elliptic curve
    Ec(EcPrivate),
    /// The private part of an `OKP` key type, probably the private part of a
    /// curve25519 or curve448 key
    Okp(OkpPrivate),
}

impl From<Private> for super::JsonWebKeyType {
    fn from(x: Private) -> Self {
        super::JsonWebKeyType::Asymmetric(Box::new(super::AsymmetricJsonWebKey::Private(x)))
    }
}

impl crate::sealed::Sealed for Private {}
impl Thumbprint for Private {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Private::Rsa(key) => key.thumbprint_prehashed(),
            Private::Ec(key) => key.thumbprint_prehashed(),
            Private::Okp(key) => key.thumbprint_prehashed(),
        }
    }
}
