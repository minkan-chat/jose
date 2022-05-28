//! Elliptic curve key types (`crv` parameter = `EC`)

pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;

use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    p521::{P521PrivateKey, P521PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};

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
