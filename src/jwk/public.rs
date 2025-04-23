use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{okp::OkpPublic, Thumbprint};
use crate::crypto::{ec, rsa};

/// The `public` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum Public {
    /// The public part of a Rsa key
    Rsa(rsa::PublicKey),
    /// The public part of an elliptic curve
    Ec(EcPublic),
    /// The public part of an `OKP` key type, probably the public part of a
    /// curve25519 or curve448 key
    Okp(OkpPublic),
}

impl crate::sealed::Sealed for Public {}
impl Thumbprint for Public {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Public::Rsa(key) => key.thumbprint_prehashed(),
            Public::Ec(key) => key.thumbprint_prehashed(),
            Public::Okp(key) => key.thumbprint_prehashed(),
        }
    }
}

/// The public part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// `Okp` variant of the [`Public`](super::Public) enum.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum EcPublic {
    /// Public part of the P-256 curve
    P256(ec::P256PublicKey),

    /// Public part of the P-384 curve
    P384(ec::P384PublicKey),

    /// Public part of the P-521 curve
    P521(ec::P521PublicKey),

    /// Public part of the secp256k1 curve
    Secp256k1(ec::Secp256k1PublicKey),
}

impl crate::sealed::Sealed for EcPublic {}
impl Thumbprint for EcPublic {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            EcPublic::P256(key) => key.thumbprint_prehashed(),
            EcPublic::P384(key) => key.thumbprint_prehashed(),
            EcPublic::P521(key) => key.thumbprint_prehashed(),
            EcPublic::Secp256k1(key) => key.thumbprint_prehashed(),
        }
    }
}

impl From<EcPublic> for super::JsonWebKeyType {
    fn from(x: EcPublic) -> Self {
        super::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
            super::AsymmetricJsonWebKey::Public(super::Public::Ec(x)),
        ))
    }
}

impl_internally_tagged_deserialize!(EcPublic, "crv", "EcCurve", [
    "P-256" => P256,
    "P-384" => P384,
    "P-521" => P521,
    "secp256k1" => Secp256k1,
]);
