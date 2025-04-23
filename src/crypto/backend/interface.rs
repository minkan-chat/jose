//! Common traits that define the API each backend must implement.

// FIXME: we should probably make sure to use `zeroize` on all
// return values of all methods on the interface traits. Most prominous
// is the rsa interface, which returns the primes and private components
// without any protection

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
}
