//! This backend implements the primitives using the [`ring`] crate

use ring::{
    digest,
    rand::{SecureRandom as _, SystemRandom},
};
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
    /// The error returned by `ring`.
    #[error("ring returned an unspecified error")]
    Unspecified,

    /// Key rejected error.
    #[error("{0}")]
    KeyRejected(ring::error::KeyRejected),

    /// Unsupported EC curve
    #[error("unsupported EcDSA curve: {0}")]
    UnsupportedCurve(&'static str),

    /// A specific feature is not supported
    #[error("ring does not support feature: {0}")]
    Unsupported(&'static str),
}

impl From<ring::error::Unspecified> for BackendError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

impl From<ring::error::KeyRejected> for BackendError {
    fn from(x: ring::error::KeyRejected) -> Self {
        Self::KeyRejected(x)
    }
}

/// The [`ring`] based backend.
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
        let rng = SystemRandom::new();
        rng.fill(buf)?;
        Ok(())
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        digest::digest(&digest::SHA256, data)
            .as_ref()
            .try_into()
            .expect("SHA256 digest length mismatch")
    }

    fn sha384(data: &[u8]) -> [u8; 48] {
        digest::digest(&digest::SHA384, data)
            .as_ref()
            .try_into()
            .expect("SHA384 digest length mismatch")
    }

    fn sha512(data: &[u8]) -> [u8; 64] {
        digest::digest(&digest::SHA512, data)
            .as_ref()
            .try_into()
            .expect("SHA512 digest length mismatch")
    }
}
