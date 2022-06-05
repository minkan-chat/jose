//! Elliptic curve key types (`crv` parameter = `EC`)

pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;

use alloc::format;
use core::fmt::Display;

use ::p256::NistP256;
use ::p384::NistP384;
use elliptic_curve::{
    bigint::ArrayEncoding,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
    AffinePoint, Curve, FieldSize, ProjectiveArithmetic, PublicKey, SecretKey,
};
use generic_array::GenericArray;
use k256::Secp256k1;
use sec1::EncodedPoint;
use serde::{de::Error as SerdeError, Deserialize, Serialize};

use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};
use crate::{base64_url::Base64UrlEncodedField, borrowable::Borrowable};

// FIXME: support all curves specified in IANA "JWK Elliptic Curve"

/// The public part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// [`Okp`](super::Public::Okp) variant of the [`Public`](super::Public) enum.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

/// The private part of some elliptic curve
///
/// Note: This does not include Curve25519 and Curve448. For these, see the
/// [`Okp`](super::Private::Okp) variant of the [`Private`](super::Private)
/// enum.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

/// Generic type for serde for public elliptic curve keys
#[derive(Deserialize)]
#[serde(bound = "")]
struct EcPublicKey<'a, C>
where
    C: Curve,
{
    #[serde(borrow)]
    pub(crate) crv: Borrowable<'a, str>,
    #[serde(borrow)]
    pub(crate) kty: Borrowable<'a, str>,
    x: Base64UrlEncodedField<C>,
    y: Base64UrlEncodedField<C>,
}

impl<'a, C> EcPublicKey<'a, C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    // FIXME: map correct errors
    pub fn to_public_key(&self) -> Result<PublicKey<C>, impl Display> {
        let point = &self.as_encoded_point();
        PublicKey::<C>::from_sec1_bytes(point.as_bytes())
    }

    pub fn as_encoded_point(&self) -> EncodedPoint<<<C>::UInt as ArrayEncoding>::ByteSize> {
        EncodedPoint::from_affine_coordinates(&self.x.0, &self.y.0, false)
    }
}

/// Generic type for serde for private elliptic curve keys
#[derive(Deserialize)]
#[serde(bound = "")]
struct EcPrivateKey<'a, C>
where
    C: Curve,
{
    #[serde(flatten)]
    #[serde(borrow)]
    pub(crate) public_part: EcPublicKey<'a, C>,
    d: Base64UrlEncodedField<C>,
}

impl<'a, C> EcPrivateKey<'a, C>
where
    C: Curve + ProjectiveArithmetic + ValidatePublicKey,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    pub fn to_secret_key(&self) -> Result<SecretKey<C>, impl Display> {
        let public = self.public_part.as_encoded_point();
        let secret = SecretKey::<C>::from_be_bytes(&self.d.0)
            .map_err(|e| format!("failed to parse secret key from big endian bytes: {}", e))?;
        C::validate_public_key(&secret, &public)
            .map_err(|e| format!("public key validation failed: {}", e))
            .map(|_| secret)
    }
}

macro_rules! impl_serde_ec {
    ($public:ty, $private:ty, $curve:literal, $key_type:literal, $inner:ty) => {
        impl<'de> Deserialize<'de> for $public {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let key = crate::jwk::ec::EcPublicKey::deserialize(deserializer)?;

                if &*key.crv != $curve {
                    return Err(<D::Error as SerdeError>::custom(format!(
                        "Invalid curve type `{}`. Expected: `{}`",
                        &*key.crv, $curve,
                    )));
                }

                if &*key.kty != $key_type {
                    return Err(<D::Error as SerdeError>::custom(format!(
                        "Invalid key type `{}`. Expected: `{}`",
                        &*key.kty, $key_type,
                    )));
                }

                Ok(Self(
                    key.to_public_key()
                        .map_err(<D::Error as SerdeError>::custom)?,
                ))
            }
        }

        impl<'de> Deserialize<'de> for $private {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let key = crate::jwk::ec::EcPrivateKey::deserialize(deserializer)?;
                if &*key.public_part.crv != $curve {
                    return Err(<D::Error as SerdeError>::custom(format!(
                        "Invalid curve type `{}`. Expected: `{}`",
                        &*key.public_part.crv, $curve,
                    )));
                }
                if &*key.public_part.kty != $key_type {
                    return Err(<D::Error as SerdeError>::custom(format!(
                        "Invalid key type `{}`. Expected: `{}`",
                        &*key.public_part.kty, $key_type,
                    )));
                }

                Ok(Self(
                    key.to_secret_key()
                        .map_err(<D::Error as SerdeError>::custom)?,
                ))
            }
        }

        impl Serialize for $public {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let key = &self.0;

                #[derive(Serialize)]
                struct Repr<'a> {
                    crv: &'a str,
                    kty: &'a str,
                    x: Base64UrlEncodedField<$inner>,
                    y: Base64UrlEncodedField<$inner>,
                }

                use elliptic_curve::sec1::ToEncodedPoint;
                let point = key.to_encoded_point(false);
                let x = point.x().map(AsRef::as_ref).unwrap_or(&[0u8][..]);
                let y = point.y().map(AsRef::as_ref).unwrap_or(&[0u8][..]);

                let repr = Repr {
                    crv: $curve,
                    kty: $key_type,
                    x: Base64UrlEncodedField(*GenericArray::from_slice(x)),
                    y: Base64UrlEncodedField(*GenericArray::from_slice(y)),
                };

                repr.serialize(serializer)
            }
        }

        impl Serialize for $private {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let key = &self.0;

                #[derive(Serialize)]
                struct Repr<'a> {
                    crv: &'a str,
                    kty: &'a str,
                    x: Base64UrlEncodedField<$inner>,
                    y: Base64UrlEncodedField<$inner>,
                    d: Base64UrlEncodedField<$inner>,
                }

                use elliptic_curve::sec1::ToEncodedPoint;
                let point = key.public_key().to_encoded_point(false);
                let x = point.x().map(AsRef::as_ref).unwrap_or(&[0u8][..]);
                let y = point.y().map(AsRef::as_ref).unwrap_or(&[0u8][..]);

                let repr = Repr {
                    crv: $curve,
                    kty: $key_type,
                    x: Base64UrlEncodedField(*GenericArray::from_slice(x)),
                    y: Base64UrlEncodedField(*GenericArray::from_slice(y)),
                    d: Base64UrlEncodedField(key.to_be_bytes()),
                };

                repr.serialize(serializer)
            }
        }
    };
}

impl_serde_ec!(P256PublicKey, P256PrivateKey, "P-256", "EC", NistP256);
impl_serde_ec!(P384PublicKey, P384PrivateKey, "P-384", "EC", NistP384);
impl_serde_ec!(
    Secp256k1PublicKey,
    Secp256k1PrivateKey,
    "secp256k1",
    "EC",
    Secp256k1
);
