/// Key Wrapping with AES Key Wrap as defined in [section 4.4 of RFC 7518]
///
/// [section 4.4 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.4>
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum AesKw {
    /// AES Key Wrap with default initial value using 128-bit key
    Aes128,
    /// AES Key Wrap with default initial value using 192-bit key
    Aes192,
    /// AES Key Wrap with default initial value using 256-bit key
    Aes256,
}

impl From<AesKw> for super::JsonWebEncryptionAlgorithm {
    fn from(x: AesKw) -> Self {
        Self::AesKw(x)
    }
}

impl From<AesKw> for super::JsonWebAlgorithm {
    fn from(x: AesKw) -> Self {
        Self::Encryption(super::JsonWebEncryptionAlgorithm::AesKw(x))
    }
}
