use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

use super::{ec::EcPrivate, okp::OkpPrivate, rsa::RsaPrivateKey};

/// The `private` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        super::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
            super::AsymmetricJsonWebKey::Private(x),
        ))
    }
}
