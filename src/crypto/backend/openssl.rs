//! This backend implements the primitives using the [OpenSSL](openssl) library.

use alloc::vec::Vec;

use thiserror::Error;

use super::interface;

pub(crate) mod ec;
pub(crate) mod hmac;
pub(crate) mod okp;
pub(crate) mod rsa;

#[allow(dead_code)] // may occurr when selecting different OpenSSL variant
#[derive(Debug, Error)]
pub(crate) enum BackendError {
    /// An error from the OpenSSL library.
    #[error(transparent)]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// No prime data was found in private key
    #[error("No prime data was found in private key")]
    NoPrimeData,

    /// A specific feature is not supported
    #[error("openssl variant does not support feature: {0}")]
    Unsupported(String),
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
        openssl::rand::rand_bytes(buf)?;
        Ok(())
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        openssl::sha::sha256(data).to_vec()
    }

    fn sha384(data: &[u8]) -> Vec<u8> {
        openssl::sha::sha384(data).to_vec()
    }

    fn sha512(data: &[u8]) -> Vec<u8> {
        openssl::sha::sha512(data).to_vec()
    }
}
