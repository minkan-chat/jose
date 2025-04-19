//! Common traits that define the API each backend must implement.

use core::{error, fmt};

pub mod hmac;

/// The backend trait that all backends must implement.
///
/// This trait is used to define some commonly used operations, like generating
/// random data.
pub trait Backend {
    /// The error type that is used by this backend.
    type Error: fmt::Debug + fmt::Display + error::Error;

    /// The HMAC key type.
    type HmacKey: hmac::Key;

    /// Fills the given buffer with random data.
    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error>;
}
