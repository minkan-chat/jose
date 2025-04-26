//! This backend implements the primitives using the [RustCrypto] ecosystem.
//!
//! [RustCrypto]: https://github.com/RustCrypto

use digest::Digest as _;
use rand_core::RngCore as _;
use thiserror::Error;

use super::interface;

pub(crate) mod ec;
pub(crate) mod hmac;
pub(crate) mod okp;
pub(crate) mod rsa;

// TODO: remove the `cfg_attr` once the RustCrypto crates implement
// the core::error::Error trait.

/// The errors that can be produced by the rust crypto backend.
#[derive(Debug, Error)]
pub(crate) enum BackendError {
    /// The error returned if the key is invalid.
    #[error("invalid key length")]
    InvalidLength,

    /// RSA operation failed.
    #[cfg_attr(feature = "std", error("an RSA operation failed"))]
    #[cfg_attr(not(feature = "std"), error("an RSA operation failed: {0}"))]
    Rsa(#[cfg_attr(feature = "std", source)] ::rsa::errors::Error),

    /// Error of the `elliptic_curve` crate.
    #[cfg_attr(feature = "std", error("an elliptic curve operation failed"))]
    #[cfg_attr(not(feature = "std"), error("an elliptic curve operation failed: {0}"))]
    EllipticCurve(#[cfg_attr(feature = "std", source)] ::elliptic_curve::Error),

    /// Error of the `ecdsa` crate.
    #[cfg_attr(feature = "std", error("an ECDSA operation failed"))]
    #[cfg_attr(not(feature = "std"), error("an ECDSA operation failed: {0}"))]
    Ecdsa(#[cfg_attr(feature = "std", source)] ::ecdsa::Error),

    /// Error of the `ed25519-dalek` crate.
    #[cfg_attr(feature = "std", error("an ED25519 operation failed"))]
    #[cfg_attr(not(feature = "std"), error("an ED25519 operation failed: {0}"))]
    Ed25519(#[cfg_attr(feature = "std", source)] ed25519_dalek::SignatureError),

    /// The amount of bytes for an EC point is invalid.
    #[error("invalid EC point length, expected {expected}, got {actual}")]
    InvalidEcPoint { expected: usize, actual: usize },

    /// The coordinates did not form a valid key.
    #[error("invalid EC key")]
    InvalidEcKey,

    /// The curve type is not supported by this backend.
    #[error("curve '{0}' not supported by this backend")]
    CurveNotSupported(&'static str),

    #[error("RSA key expected to have exactly 2 prime numbers")]
    RsaTwoPrimes,

    /// `rand_core` error.
    #[cfg_attr(feature = "std", error("failed to generate random data"))]
    #[cfg_attr(not(feature = "std"), error("failed to generate random data: {0}"))]
    Rand(#[cfg_attr(feature = "std", source)] rand_core::Error),
}

impl From<digest::InvalidLength> for BackendError {
    fn from(_: digest::InvalidLength) -> Self {
        Self::InvalidLength
    }
}

impl From<::rsa::errors::Error> for BackendError {
    fn from(x: ::rsa::errors::Error) -> Self {
        Self::Rsa(x)
    }
}

/// The [RustCrypto] based backend.
///
/// [RustCrypto]: https://github.com/RustCrypto
#[derive(Debug)]
pub(crate) enum Backend {}

impl interface::Backend for Backend {
    type EcPrivateKey = ec::PrivateKey;
    type EcPublicKey = ec::PublicKey;
    type EdPrivateKey = okp::PrivateKey;
    type EdPublicKey = okp::PublicKey;
    type Error = BackendError;
    type HmacKey = hmac::Key;
    type RsaPrivateKey = rsa::PrivateKey;
    type RsaPublicKey = rsa::PublicKey;

    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error> {
        use rand_core::OsRng;

        OsRng.try_fill_bytes(buf).map_err(BackendError::Rand)?;
        Ok(())
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(data).into()
    }

    fn sha384(data: &[u8]) -> [u8; 48] {
        sha2::Sha384::digest(data).into()
    }

    fn sha512(data: &[u8]) -> [u8; 64] {
        sha2::Sha512::digest(data).into()
    }
}
