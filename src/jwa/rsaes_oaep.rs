/// Key Encryption with RSAES OAEP as defined in [section 4.3 of RFC 7518]
///
/// [section 4.3 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.3>
#[derive(Debug)]
pub enum RsaesOaep {
    /// RSAES OAEP using default parameters
    RsaesOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RsaesOaep256,
}
