use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    p521::{P521PrivateKey, P521PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};

/// Key types for the P-256 curve
pub mod p256 {
    use elliptic_curve::{PublicKey, SecretKey};
    use p256::NistP256;

    /// A P-256 public key used to verify signatures and/or encrypt
    #[derive(Debug)]
    pub struct P256PublicKey(PublicKey<NistP256>);
    /// A P-256 private key used to create signatures and/or decrypt
    #[derive(Debug)]
    pub struct P256PrivateKey(SecretKey<NistP256>);
}

/// TODO: unsupported, see <https://github.com/RustCrypto/elliptic-curves/issues/240>
#[allow(missing_docs)]
pub mod p384 {

    #[derive(Debug)]
    pub struct P384PublicKey();
    #[derive(Debug)]
    pub struct P384PrivateKey();
}

/// TODO: unsupported, see <https://github.com/RustCrypto/elliptic-curves/issues/114>
#[allow(missing_docs)]
pub mod p521 {
    #[derive(Debug)]
    pub struct P521PublicKey();
    #[derive(Debug)]
    pub struct P521PrivateKey();
}

/// Key types for the secp256k1 (a.k.a. K-256) curve
pub mod secp256k1 {
    use elliptic_curve::{PublicKey, SecretKey};
    use k256::Secp256k1;

    /// A secp256k1 public key used to verify signatures and/or encrypt
    #[derive(Debug)]
    pub struct Secp256k1PublicKey(PublicKey<Secp256k1>);
    /// A secp256k1 private key used to create signatures and/or decrypt
    #[derive(Debug)]
    pub struct Secp256k1PrivateKey(SecretKey<Secp256k1>);
}

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
