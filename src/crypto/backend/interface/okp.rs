//! The interfaces for OKP/ED keys.

use alloc::vec::Vec;

use secrecy::SecretSlice;

use crate::crypto::Result;

/// The common operations for a ED public key.
pub(crate) trait PublicKey: Sized + Clone {
    /// Creates a new public key from the given data.
    fn new(alg: CurveAlgorithm, x: Vec<u8>) -> Result<Self>;

    /// Returns the encoded bytes for this public key.
    fn to_bytes(&self) -> Vec<u8>;

    /// Verifies if the message is valid for the given signature and algorithm.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool>;
}

/// The common operations for a ED private key.
pub(crate) trait PrivateKey: Sized + Clone {
    /// The signature type that is produced by this key.
    type Signature: Into<Vec<u8>> + AsRef<[u8]>;

    /// The public key type.
    type PublicKey: PublicKey;

    /// Generates a new secure random private key.
    fn generate(alg: CurveAlgorithm) -> Result<Self>;

    /// Creates a new private key from the given data.
    fn new(alg: CurveAlgorithm, x: Vec<u8>, d: SecretSlice<u8>) -> Result<Self>;

    /// Returns the public key that belongs to this private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the encoded bytes for this private key.
    fn to_bytes(&self) -> SecretSlice<u8>;

    /// Signs the given data using this key.
    ///
    /// This operation **must** be re-usable, meaning this method can be
    /// called multiple times with different data to sign.
    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature>;
}

/// The different curve algorithm combinations that can be supported
/// by a crypto backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurveAlgorithm {
    /// The Ed25519 curve.
    Ed25519,
    /// The Ed448 curve.
    Ed448,
}
