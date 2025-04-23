use alloc::{boxed::Box, string::String};

use serde::{Deserialize, Serialize};

use super::{okp::OkpPrivate, Thumbprint};
use crate::crypto::{ec, rsa};

/// The `private` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum Private {
    /// The private part of a Rsa key
    Rsa(Box<rsa::PrivateKey>),
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

/// The private part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// `Okp` variant of the [`Private`](super::Private)
/// enum.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum EcPrivate {
    /// Private part of the P-256 curve
    P256(ec::P256PrivateKey),
    /// Private part of the P-384 curve
    P384(ec::P384PrivateKey),
    /// Private part of the P-521 curve
    P521(ec::P521PrivateKey),
    /// Private part of the secp256k1 curve
    Secp256k1(ec::Secp256k1PrivateKey),
}

impl crate::sealed::Sealed for EcPrivate {}
impl Thumbprint for EcPrivate {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            EcPrivate::P256(key) => key.thumbprint_prehashed(),
            EcPrivate::P384(key) => key.thumbprint_prehashed(),
            EcPrivate::P521(key) => key.thumbprint_prehashed(),
            EcPrivate::Secp256k1(key) => key.thumbprint_prehashed(),
        }
    }
}

impl From<EcPrivate> for super::JsonWebKeyType {
    fn from(x: EcPrivate) -> Self {
        super::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
            super::AsymmetricJsonWebKey::Private(super::Private::Ec(x)),
        ))
    }
}

impl_internally_tagged_deserialize!(EcPrivate, "crv", "EcCurve", [
    "P-256" => P256,
    "P-384" => P384,
    "P-521" => P521,
    "secp256k1" => Secp256k1,
]);
