/// Digital Signature with RSASSA-PKCS1-v1_5 as defined in [section 3.3 of RFC
/// 7518]
///
/// [section 3.3 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.3>
#[derive(Debug)]
pub enum RsassaPkcs1V1_5 {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    Rs512,
}
