//! Common traits that define the API each backend must implement.

use core::{error, fmt};

pub(crate) mod hmac;
pub(crate) mod rsa;

/// The backend trait that all backends must implement.
///
/// This trait is used to define some commonly used operations, like generating
/// random data.
pub(crate) trait Backend {
    /// The error type that is used by this backend.
    type Error: fmt::Debug + fmt::Display + error::Error;

    /// The HMAC key type.
    type HmacKey: hmac::Key;

    /// The RSA private key type.
    type RsaPrivateKey: rsa::PrivateKey;

    /// The RSA public key type.
    type RsaPublicKey: rsa::PublicKey;

    /// Fills the given buffer with random data.
    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error>;
}
