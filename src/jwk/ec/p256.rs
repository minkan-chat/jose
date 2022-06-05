//! Key types for the P-256 curve
use elliptic_curve::{PublicKey, SecretKey};
use p256::NistP256;

/// A P-256 public key used to verify signatures and/or encrypt
#[derive(Debug, PartialEq, Eq)]
pub struct P256PublicKey(pub(super) PublicKey<NistP256>);
/// A P-256 private key used to create signatures and/or decrypt
#[derive(Debug, PartialEq, Eq)]
pub struct P256PrivateKey(pub(super) SecretKey<NistP256>);
