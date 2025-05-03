//! This backend implements the primitives using the [OpenSSL](openssl) library.

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

    fn sha256(data: &[u8]) -> [u8; 32] {
        openssl::sha::sha256(data)
    }

    fn sha384(data: &[u8]) -> [u8; 48] {
        openssl::sha::sha384(data)
    }

    fn sha512(data: &[u8]) -> [u8; 64] {
        openssl::sha::sha512(data)
    }
}

/// Wrapper around a [`BigNum`](openssl::bn::BigNum) that is cleared on drop.
struct ZeroizingBigNum(openssl::bn::BigNum);

impl ZeroizingBigNum {
    fn from_slice(slice: &[u8]) -> Result<Self, BackendError> {
        let bn = openssl::bn::BigNum::from_slice(slice)?;
        Ok(Self(bn))
    }
}

impl Drop for ZeroizingBigNum {
    fn drop(&mut self) {
        self.0.clear();
    }
}
