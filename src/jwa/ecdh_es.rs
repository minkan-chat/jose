use super::AesKw;

/// Different modes ECDH-ES can be used as defined in [section 4.6 of RFC 7518]
///
/// [section 4.6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.6>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcDhES {
    /// Using ECDH-ES directly without any wrapping
    Direct,
    /// ECDH-ES using Concat KDF and CEK wrapped with one variant of [AesKw]
    AesKw(AesKw),
}

impl From<EcDhES> for super::JsonWebEncryptionAlgorithm {
    fn from(x: EcDhES) -> Self {
        Self::EcDhES(x)
    }
}

impl From<EcDhES> for super::JsonWebAlgorithm {
    fn from(x: EcDhES) -> Self {
        Self::Encryption(super::JsonWebEncryptionAlgorithm::EcDhES(x))
    }
}
