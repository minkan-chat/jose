//! This backend implements the primitives using the [RustCrypto] ecosystem.
//!
//! [RustCrypto]: https://github.com/RustCrypto

use rand::RngCore as _;
use thiserror::Error;

use super::interface;

pub mod hmac;

/// The errors that can be produced by the rust crypto backend.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The error returned if the key is invalid.
    #[error("invalid key length")]
    InvalidLength,
}

impl From<digest::InvalidLength> for BackendError {
    fn from(_: digest::InvalidLength) -> Self {
        Self::InvalidLength
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

    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error> {
        use rand_core::OsRng;

        OsRng.fill_bytes(buf);
        Ok(())
    }
}
