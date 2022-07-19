//! Key types for the secp256k1 (a.k.a. K-256) curve
use elliptic_curve::{PublicKey, SecretKey};
use k256::Secp256k1;

/// A secp256k1 public key used to verify signatures and/or encrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secp256k1PublicKey(PublicKey<Secp256k1>);

/// A Secp256k1 private key used to create signatures and/or decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secp256k1PrivateKey(SecretKey<Secp256k1>);

impl_serde_ec!(
    Secp256k1PublicKey,
    Secp256k1PrivateKey,
    "secp256k1",
    "EC",
    Secp256k1
);

impl_ec!(
    Secp256k1Signer,
    Secp256k1PrivateKey,
    Secp256k1,
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es256K),
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es256K),
    Secp256k1Verifier,
    Secp256k1PublicKey
);
