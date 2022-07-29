/// Key Encryption with RSAES OAEP as defined in [section 4.3 of RFC 7518]
///
/// [section 4.3 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.3>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsaesOaep {
    /// RSAES OAEP using default parameters
    RsaesOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RsaesOaep256,
}

impl From<RsaesOaep> for crate::jwa::JsonWebEncryptionAlgorithm {
    fn from(x: RsaesOaep) -> Self {
        Self::RsaesOaep(x)
    }
}

impl From<RsaesOaep> for crate::jwa::JsonWebAlgorithm {
    fn from(x: RsaesOaep) -> Self {
        Self::Encryption(crate::jwa::JsonWebEncryptionAlgorithm::RsaesOaep(x))
    }
}
