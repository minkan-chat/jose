//! This backend implements the primitives using the [RustCrypto] ecosystem.
//!
//! [RustCrypto]: https://github.com/RustCrypto

use rand::RngCore as _;
use thiserror::Error;

use super::interface;

pub mod hmac;
pub mod rsa;

// TODO: remove the `cfg_attr` once the RustCrypto crates implement
// the core::error::Error trait.

/// The errors that can be produced by the rust crypto backend.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The error returned if the key is invalid.
    #[error("invalid key length")]
    InvalidLength,

    /// RSA operation failed.
    #[cfg_attr(feature = "std", error("an RSA operation failed"))]
    #[cfg_attr(not(feature = "std"), error("an RSA operation failed: {0}"))]
    Rsa(#[cfg_attr(feature = "std", source)] ::rsa::errors::Error),
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
pub enum Backend {}

impl interface::Backend for Backend {
    type Error = BackendError;
    type HmacKey = hmac::Key;
    type RsaPrivateKey = rsa::PrivateKey;
    type RsaPublicKey = rsa::PublicKey;

    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error> {
        use rand_core::OsRng;

        OsRng.fill_bytes(buf);
        Ok(())
    }
}
