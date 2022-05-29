//! Elliptic curve key types (`crv` parameter = `EC`)

pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;

use elliptic_curve::{
    bigint::ArrayEncoding,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
    AffinePoint, Curve, Field, FieldSize, ProjectiveArithmetic, PublicKey, SecretKey,
};
use sec1::EncodedPoint;
use serde::Deserialize;

use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    p521::{P521PrivateKey, P521PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};
use crate::base64_url::Base64UrlEncodedField;

/// The public part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// [`Okp`](super::Public::Okp) variant of the [`Public`](super::Public) enum.
#[non_exhaustive]
#[derive(Debug)]
pub enum EcPublic {
    /// Public part of the P-256 curve
    P256(P256PublicKey),
    /// Public part of the P-384 curve
    P384(P384PublicKey),
    /// Public part of the P-521 curve
    P521(P521PublicKey),
    /// Public part of the secp251k1 curve
    Secp256k1(Secp256k1PublicKey),
}

/// The private part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// [`Okp`](super::Private::Okp) variant of the [`Private`](super::Private)
/// enum.
#[non_exhaustive]
#[derive(Debug)]
pub enum EcPrivate {
    /// Private part of the P-256 curve
    P256(P256PrivateKey),
    /// Private part of the P-384 curve
    P384(P384PrivateKey),
    /// Private part of the P-521 curve
    P521(P521PrivateKey),
    /// Private part of the secp251k1 curve
    Secp256k1(Secp256k1PrivateKey),
}

#[derive(Deserialize)]
#[serde(bound = "")]
pub(self) struct EcPublicKey<C>
where
    C: Curve,
{
    x: Base64UrlEncodedField<C>,
    y: Base64UrlEncodedField<C>,
}

impl<C> EcPublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    // FIXME: map correct errors
    pub fn to_public_key(&self) -> Result<PublicKey<C>, &'static str> {
        let point = &self.as_encoded_point();
        Ok(PublicKey::<C>::from_sec1_bytes(point.as_bytes()).unwrap())
    }

    pub fn as_encoded_point(&self) -> EncodedPoint<<<C>::UInt as ArrayEncoding>::ByteSize> {
        EncodedPoint::from_affine_coordinates(&self.x.0, &self.y.0, false)
    }
}

#[derive(Deserialize)]
#[serde(bound = "")]
pub(self) struct EcPrivateKey<C>
where
    C: Curve,
{
    #[serde(flatten)]
    public_part: EcPublicKey<C>,
    d: Base64UrlEncodedField<C>,
}

impl<C> EcPrivateKey<C>
where
    C: Curve + ProjectiveArithmetic + ValidatePublicKey,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    pub fn to_secret_key(&self) -> Result<SecretKey<C>, &'static str> {
        let public = self.public_part.as_encoded_point();
        let secret = SecretKey::<C>::from_be_bytes(&self.d.0).unwrap();
        C::validate_public_key(&secret, &public).unwrap();
        Ok(secret)
    }
}
