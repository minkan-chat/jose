use crate::{
    header::HeaderValue,
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm},
    sealed::Sealed,
};

#[derive(Debug)]
pub struct Jwe {
    /// `alg` parameter
    pub(crate) algorithm: HeaderValue<JsonWebEncryptionAlgorithm>,
    /// `enc` parameter
    pub(crate) content_encryption_algorithm: HeaderValue<JsonWebContentEncryptionAlgorithm>,
}

impl Sealed for Jwe {}
