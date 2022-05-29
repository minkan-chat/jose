//! Key types for the secp256k1 (a.k.a. K-256) curve
use elliptic_curve::{PublicKey, SecretKey};
use k256::Secp256k1;

/// A secp256k1 public key used to verify signatures and/or encrypt
#[derive(Debug)]
pub struct Secp256k1PublicKey(pub(super) PublicKey<Secp256k1>);
/// A secp256k1 private key used to create signatures and/or decrypt
#[derive(Debug)]
pub struct Secp256k1PrivateKey(pub(super) SecretKey<Secp256k1>);
