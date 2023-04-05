use crate::{
    header::HeaderValue,
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm},
    sealed::Sealed,
};

/// Parameters specific to Json Web Encryption
#[derive(Debug)]
#[non_exhaustive]
pub struct Jwe {
    /// `alg` parameter
    pub(crate) algorithm: HeaderValue<JsonWebEncryptionAlgorithm>,
    /// `enc` parameter
    pub(crate) content_encryption_algorithm: HeaderValue<JsonWebContentEncryptionAlgorithm>,
    // FIXME: other JWE parameters (zip, epk, ...)
}

impl Sealed for Jwe {}
