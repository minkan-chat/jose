//! Common traits that define the API each backend must implement.

use core::{error, fmt};

pub(crate) mod ec;
pub(crate) mod hmac;
pub(crate) mod okp;
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

    /// The EC public key type.
    type EcPublicKey: ec::PublicKey;

    /// The EC private key type.
    type EcPrivateKey: ec::PrivateKey;

    /// The ED public key type.
    type EdPublicKey: okp::PublicKey;

    /// The ED private key type.
    type EdPrivateKey: okp::PrivateKey;

    /// Fills the given buffer with random data.
    fn fill_random(buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Performs a quick Sha256 of the given data.
    fn sha256(data: &[u8]) -> [u8; 32];

    /// Performs a quick Sha384 of the given data.
    fn sha384(data: &[u8]) -> [u8; 48];

    /// Performs a quick Sha512 of the given data.
    fn sha512(data: &[u8]) -> [u8; 64];
}
