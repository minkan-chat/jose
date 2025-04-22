//! The interfaces for RSA.

use alloc::vec::Vec;
use core::fmt;

use crate::{crypto::Result, jwa};

/// Part of the [`PrivateKeyComponents`], which includes additional information
/// about the prime numbers.
#[expect(unused)]
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
    pub public: PublicKeyComponents,
    pub d: Vec<u8>,
    pub prime: PrivateKeyPrimeComponents,
}

/// The components of a public key.
///
/// All fields in this struct are of type `Vec<u8>` and are
/// big integers represented in big endian bytes.
pub(crate) struct PublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// The common operations for an RSA private key.
pub(crate) trait PrivateKey: Sized {
    /// The signature type that is produced by this key.
    type Signature: Into<Vec<u8>> + AsRef<[u8]>;

    /// The public key type.
    type PublicKey: PublicKey<BigInt = Self::BigInt>;

    /// The bigint type used for the key.
    type BigInt: BigInt;

    /// Creates a new RSA private key from the given private key components.
    fn from_components(components: PrivateKeyComponents) -> Result<Self>;

    /// Creates a new public key from this private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the prime numbers used for this key.
    fn primes(&self) -> Vec<Self::BigInt>;

    /// Returns the public key component `n`.
    fn n(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the public key component `e`.
    fn e(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the private key component `d`.
    fn d(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the First Factor CRT Exponent
    fn dp(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the Second Factor CRT Exponent
    fn dq(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the First CRT Coefficient
    fn qi(&self) -> Self::BigInt;

    /// Signs the given data using this key.
    ///
    /// This operation **must** be re-usable, meaning this method can be
    /// called multiple times with different data to sign.
    fn sign(&mut self, alg: jwa::RsaSigning, data: &[u8]) -> Result<Self::Signature>;
}

/// The common operations for an RSA public key.
pub(crate) trait PublicKey: Sized {
    /// The bigint type used for the key.
    type BigInt: BigInt;

    /// Creates a new RSA public key from the given public key components.
    fn from_components(components: PublicKeyComponents) -> Result<Self>;

    /// Returns the public key component `n`.
    fn n(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Returns the public key component `e`.
    fn e(&self) -> &<Self::BigInt as BigInt>::Ref;

    /// Verifies if the message is valid for the given signature and algorithm.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn verify(&mut self, alg: jwa::RsaSigning, msg: &[u8], signature: &[u8]) -> Result<bool>;
}

/// The BigInt trait is used to define the operations that are needed for
/// working with big integers.
pub(crate) trait BigInt: Sized + PartialEq + Eq {
    /// The reference to a bigint of this type.
    type Ref: fmt::Debug + BigIntRef;
}

/// The BigIntRef trait is used to define the operations that are needed for
/// working with reference to big integers.
pub(crate) trait BigIntRef {
    /// Returns the bytes for this bigint in Big endian order.
    fn to_bytes_be(&self) -> Vec<u8>;
}
