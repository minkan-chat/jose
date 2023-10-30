//! Elliptic curve key types (`crv` parameter = `EC`)

pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;

use alloc::{format, string::String};
use core::fmt::Display;

use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
    Curve, CurveArithmetic, PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};

use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};
use super::Thumbprint;
use crate::{base64_url::Base64UrlEncodedField, tagged_visitor::TaggedContentVisitor};

// FIXME: support all curves specified in IANA "JWK Elliptic Curve"

/// The public part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// `Okp` variant of the [`Public`](super::Public) enum.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EcPublic {
    /// Public part of the P-256 curve
    P256(P256PublicKey),
    /// Public part of the P-384 curve
    P384(P384PublicKey),
    // /// Public part of the P-521 curve
    // P521(P521PublicKey),
    /// Public part of the secp251k1 curve
    Secp256k1(Secp256k1PublicKey),
}

impl crate::sealed::Sealed for EcPublic {}
impl Thumbprint for EcPublic {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            EcPublic::P256(key) => key.thumbprint_prehashed(),
            EcPublic::P384(key) => key.thumbprint_prehashed(),
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
    "secp256k1" => Secp256k1,
]);

/// The private part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// `Okp` variant of the [`Private`](super::Private)
/// enum.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EcPrivate {
    /// Private part of the P-256 curve
    P256(P256PrivateKey),
    /// Private part of the P-384 curve
    P384(P384PrivateKey),
    // /// Private part of the P-521 curve
    // P521(P521PrivateKey),
    /// Private part of the secp251k1 curve
    Secp256k1(Secp256k1PrivateKey),
}

impl crate::sealed::Sealed for EcPrivate {}
impl Thumbprint for EcPrivate {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            EcPrivate::P256(key) => key.thumbprint_prehashed(),
            EcPrivate::P384(key) => key.thumbprint_prehashed(),
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
    "secp256k1" => Secp256k1,
]);

/// Generic type for serde for public elliptic curve keys
#[derive(Deserialize)]
#[serde(bound = "")]
struct EcPublicKey<C>
where
    C: Curve,
{
    pub(crate) crv: String,
    pub(crate) kty: String,
    x: Base64UrlEncodedField<C>,
    y: Base64UrlEncodedField<C>,
}

impl<C> EcPublicKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    // FIXME: map correct errors
    pub fn to_public_key(&self) -> Option<PublicKey<C>> {
        let point = &self.as_encoded_point();
        PublicKey::<C>::from_encoded_point(point).into()
    }

    pub fn as_encoded_point(&self) -> EncodedPoint<C> {
        EncodedPoint::<C>::from_affine_coordinates(&self.x.0, &self.y.0, false)
    }
}

/// Generic type for serde for private elliptic curve keys
#[derive(Deserialize)]
#[serde(bound = "")]
struct EcPrivateKey<C>
where
    C: Curve,
{
    #[serde(flatten)]
    pub(crate) public_part: EcPublicKey<C>,
    d: Base64UrlEncodedField<C>,
}

impl<C> EcPrivateKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    pub fn to_secret_key(&self) -> Result<SecretKey<C>, impl Display> {
        let public = self.public_part.as_encoded_point();
        let secret = SecretKey::<C>::from_bytes(&self.d.0)
            .map_err(|e| format!("failed to parse secret key from big endian bytes: {}", e))?;
        C::validate_public_key(&secret, &public)
            .map_err(|e| format!("public key validation failed: {}", e))
            .map(|_| secret)
    }
}
