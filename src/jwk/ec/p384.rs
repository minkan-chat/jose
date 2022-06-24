//! Key types for the P-384 curve

use elliptic_curve::{PublicKey, SecretKey};
use p384::NistP384;

/// A P-384 public key used to verify signatures and/or encrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384PublicKey(pub(super) PublicKey<NistP384>);

/// A P-384 private key used to create signatures and/or decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384PrivateKey(pub(super) SecretKey<NistP384>);
