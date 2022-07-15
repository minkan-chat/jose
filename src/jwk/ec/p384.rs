//! Key types for the P-384 curve

use elliptic_curve::{PublicKey, SecretKey};
use p384::NistP384;

/// A P-384 public key used to verify signatures and/or encrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384PublicKey(PublicKey<NistP384>);

/// A P-384 private key used to create signatures and/or decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384PrivateKey(SecretKey<NistP384>);

impl_serde_ec!(P384PublicKey, P384PrivateKey, "P-384", "EC", NistP384);

impl_ec!(
    /// A [`Signer`](crate::jws::Signer) using a [`P384PrivateKey`]
    P384Signer,
    P384PrivateKey,
    NistP384,
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es384),
    crate::jwa::JsonWebSigningAlgorithm::EcDSA(crate::jwa::EcDSA::Es384),
    /// A [`Verifier`](crate::jws::Verifier) using a [`P384PublicKey`]
    P384Verifier,
    P384PublicKey
);
