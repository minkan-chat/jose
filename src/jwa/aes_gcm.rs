use serde_json::Value;

/// Key Encryption with AES GCM as defined in [section 4.7 of RFC 7518]
///
/// [section 4.7 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.7>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcm {
    /// The "iv" (Initialization Vector) Header Parameter as defined in [section
    /// 4.7.1.1]
    ///
    /// [section 4.7.1.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1>
    pub iv: Value,
    /// The "tag" (Authentication Tag) Header Parameter as defined in [section
    /// 4.7.1.2]
    ///
    /// [section 4.7.1.2]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2>
    pub tag: Value,
    /// The variant of AES that will be used
    pub variant: AesGcmVariant,
}

/// Different variants of AES GCM as in the table in [section 4.7 of RFC 7518]
///
/// [section 4.7 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.7>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesGcmVariant {
    /// Key wrapping with AES GCM using 128-bit key
    Aes128,
    /// Key wrapping with AES GCM using 192-bit key
    Aes192,
    /// Key wrapping with AES GCM using 256-bit key
    Aes256,
}
