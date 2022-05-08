/// Digital Signature with RSASSA-PSS as defined in [section 3.5 of RFC 7518]
///
/// [section 3.5 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.5>
#[derive(Debug)]
pub enum RsassaPss {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    Ps256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    Ps384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    Ps512,
}
