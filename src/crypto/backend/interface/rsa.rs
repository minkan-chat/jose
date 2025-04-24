//! The interfaces for RSA.

use alloc::vec::Vec;

use crate::{crypto::Result, jwa};

// TODO: implement `Zeroize` for the `PrivateKeyComponents` and make sure all
// values are zeroized correctly

/// Part of the [`PrivateKeyComponents`], which includes additional information
/// about the prime numbers.
pub(crate) struct PrivateKeyPrimeComponents {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qi: Vec<u8>,
}

/// The components of a private key.
///
/// All fields in this struct are of type `Vec<u8>` and are
/// big integers represented in big endian bytes.
pub(crate) struct PrivateKeyComponents {
    pub d: Vec<u8>,
    pub prime: PrivateKeyPrimeComponents,
}

/// The components of a public key.
///
/// All fields in this struct are of type `Vec<u8>` and are
/// big integers represented in big endian bytes.
#[derive(PartialEq, Eq)]
pub(crate) struct PublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// The common operations for an RSA private key.
pub(crate) trait PrivateKey: Sized {
    /// The signature type that is produced by this key.
    type Signature: Into<Vec<u8>> + AsRef<[u8]>;

    /// The public key type.
    type PublicKey: PublicKey;

    /// Generates a new rsa private key with the given number of bits.
    fn generate(bits: usize) -> Result<Self>;

    /// Creates a new RSA private key from the given private & public key
    /// components.
    fn from_components(private: PrivateKeyComponents, public: PublicKeyComponents) -> Result<Self>;

    /// Creates a new public key from this private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the private key components.
    fn private_components(&self) -> Result<PrivateKeyComponents>;

    /// Returns the public key components.
    fn public_components(&self) -> PublicKeyComponents;

    /// Signs the given data using this key.
    ///
    /// This operation **must** be re-usable, meaning this method can be
    /// called multiple times with different data to sign.
    fn sign(&mut self, alg: jwa::RsaSigning, data: &[u8]) -> Result<Self::Signature>;
}

/// The common operations for an RSA public key.
pub(crate) trait PublicKey: Sized {
    /// Creates a new RSA public key from the given public key components.
    fn from_components(components: PublicKeyComponents) -> Result<Self>;

    /// Returns the public key components.
    fn components(&self) -> PublicKeyComponents;

    /// Verifies if the message is valid for the given signature and algorithm.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn verify(&mut self, alg: jwa::RsaSigning, msg: &[u8], signature: &[u8]) -> Result<bool>;
}
