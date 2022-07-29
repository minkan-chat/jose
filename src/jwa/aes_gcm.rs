/// Different variants of AES GCM as in the table in [section 4.7 of RFC 7518]
///
/// [section 4.7 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.7>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesGcm {
    /// Key wrapping with AES GCM using 128-bit key
    Aes128,
    /// Key wrapping with AES GCM using 192-bit key
    Aes192,
    /// Key wrapping with AES GCM using 256-bit key
    Aes256,
}

impl From<AesGcm> for super::JsonWebEncryptionAlgorithm {
    fn from(x: AesGcm) -> Self {
        Self::AesGcmKw(x)
    }
}

impl From<AesGcm> for super::JsonWebAlgorithm {
    fn from(x: AesGcm) -> Self {
        Self::Encryption(super::JsonWebEncryptionAlgorithm::AesGcmKw(x))
    }
}
