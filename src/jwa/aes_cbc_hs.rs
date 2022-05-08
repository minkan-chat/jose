/// Authenticated encryption algorithms built using a composition of AES in
/// Cipher Block Chaining (CBC) mode and HMAC as defined in [section 5.2 of RFC
/// 7518]
///
/// [section 5.2 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.2>
#[derive(Debug)]
pub enum AesCbcHs {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption as defined in [section
    /// 5.2.3]
    ///
    /// [section 5.2.3]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3>
    Aes128CbcHs256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm as defined
    /// in [section 5.2.4]
    ///
    /// [section 5.2.4]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4>
    Aes192CbsHs384,

    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm as defined
    /// in [section 5.2.5]
    ///
    /// [section 5.2.5]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5>
    Aes256CbcHs512,
}
