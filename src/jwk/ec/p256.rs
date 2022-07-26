//! Key types for the P-256 curve
use elliptic_curve::{PublicKey, SecretKey};
use p256::NistP256;

/// A P-256 public key used to verify signatures and/or encrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256PublicKey(PublicKey<NistP256>);
/// A P-256 private key used to create signatures and/or decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256PrivateKey(SecretKey<NistP256>);

impl_serde_ec!(P256PublicKey, P256PrivateKey, "P-256", "EC", NistP256);

impl_ec!(
    P256Signer,
    P256PrivateKey,
    NistP256,
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es256),
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es256),
    P256,
    P256Verifier,
    P256PublicKey
);
