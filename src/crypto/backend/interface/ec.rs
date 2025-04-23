//! The interfaces for EC keys.

use alloc::vec::Vec;

use crate::{crypto::Result, jwa};

/// The common operations for a curve-generic EC public key.
pub(crate) trait PublicKey: Sized + Clone {
    /// The coordinate type of the curve.
    type Coordinate: Into<Vec<u8>> + AsRef<[u8]>;

    /// Creates a new public key from the given data.
    fn new(alg: jwa::EcDSA, x: Vec<u8>, y: Vec<u8>) -> Result<Self>;

    /// Returns the (x, y) coordinates of the public key.
    fn to_point(&self) -> (Self::Coordinate, Self::Coordinate);

    /// Verifies if the message is valid for the given signature and algorithm.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool>;
}

/// The common operations for a curve-generic EC private key.
pub(crate) trait PrivateKey: Sized + Clone {
    /// The signature type that is produced by this key.
    type Signature: Into<Vec<u8>> + AsRef<[u8]>;

    /// The public key type.
    type PublicKey: PublicKey;

    /// The private key material.
    type PrivateKeyMaterial: Into<Vec<u8>>;

    /// Creates a new private key from the given data.
    fn new(alg: jwa::EcDSA, x: Vec<u8>, y: Vec<u8>, d: Vec<u8>) -> Result<Self>;

    /// Generates a new secure random private key.
    fn generate(alg: jwa::EcDSA) -> Result<Self>;

    /// Returns the private key material of this key.
    fn private_material(&self) -> Self::PrivateKeyMaterial;

    /// Returns the public part of this key, a (x, y) coordinates.
    fn public_point(
        &self,
    ) -> (
        <Self::PublicKey as PublicKey>::Coordinate,
        <Self::PublicKey as PublicKey>::Coordinate,
    );

    /// Returns the public key of this private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Signs the given data using this key.
    ///
    /// This operation **must** be re-usable, meaning this method can be
    /// called multiple times with different data to sign.
    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature>;
}
