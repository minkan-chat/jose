/// A variant of Key Encryption with PBES2 as defined in the table of [section
/// 4.8 of RFC 7518]
///
/// [section 4.8 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.8>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pbes2 {
    /// PBES2 with HMAC SHA56 and "A128KW" wrapping
    Hs256Aes128,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Hs384Aes192,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Hs512Aes256,
}

impl From<Pbes2> for super::JsonWebEncryptionAlgorithm {
    fn from(x: Pbes2) -> Self {
        Self::Pbes2(x)
    }
}

impl From<Pbes2> for super::JsonWebAlgorithm {
    fn from(x: Pbes2) -> Self {
        Self::Encryption(super::JsonWebEncryptionAlgorithm::Pbes2(x))
    }
}
