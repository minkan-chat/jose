use serde_json::Value;

/// Key Encryption with PBES2 as defined in [section 4.8 of RFC 7518]
///
/// [section 4.8 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.8>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbes2 {
    /// The "p2s" (PBES2 Salt Input) Header Parameter as defined in [section
    /// 4.8.1.1]
    ///
    /// [section 4.8.1.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1>
    pub p2s: Value,
    /// The "p2c" (PBES2 Count) Header Parameter as defined in [section 4.8.1.2]
    ///
    /// [section 4.8.1.2]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2>
    pub p2c: Value,
    /// The variant of PBES2 that will be used
    pub variant: Pbes2Variant,
}

/// A variant of Key Encryption with PBES2 as defined in the table of [section
/// 4.8 of RFC 7518]
///
/// [section 4.8 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.8>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pbes2Variant {
    /// PBES2 with HMAC SHA56 and "A128KW" wrapping
    Hs256Aes128,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Hs384Aes192,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Hs512Aes256,
}
