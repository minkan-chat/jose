use self::{
    p256::{P256PrivateKey, P256PublicKey},
    p384::{P384PrivateKey, P384PublicKey},
    secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
};

pub mod p256 {
    use elliptic_curve::{PublicKey, SecretKey};
    use p256::NistP256;

    #[derive(Debug)]
    pub struct P256PublicKey(PublicKey<NistP256>);
    #[derive(Debug)]
    pub struct P256PrivateKey(SecretKey<NistP256>);
}

// TODO: unsupported, see <https://github.com/RustCrypto/elliptic-curves/issues/240>
pub mod p384 {

    #[derive(Debug)]
    pub struct P384PublicKey();
    #[derive(Debug)]
    pub struct P384PrivateKey();
}

// TODO: unsupported, see <https://github.com/RustCrypto/elliptic-curves/issues/114>
pub mod p521 {
    #[derive(Debug)]
    pub struct P521PublicKey();
    #[derive(Debug)]
    pub struct P521PrivateKey();
}

pub mod secp256k1 {
    use elliptic_curve::{PublicKey, SecretKey};
    use k256::Secp256k1;

    #[derive(Debug)]
    pub struct Secp256k1PublicKey(PublicKey<Secp256k1>);
    #[derive(Debug)]
    pub struct Secp256k1PrivateKey(SecretKey<Secp256k1>);
}

#[non_exhaustive]
#[derive(Debug)]
pub enum EcPublic {
    P256(P256PublicKey),
    P384(P384PublicKey),
    P521(P384PublicKey),
    Secp256k1(Secp256k1PublicKey),
}

#[non_exhaustive]
#[derive(Debug)]
pub enum EcPrivate {
    P256(P256PrivateKey),
    P384(P384PrivateKey),
    P521(P384PrivateKey),
    Secp256k1(Secp256k1PrivateKey),
}
