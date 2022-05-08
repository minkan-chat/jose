/// HMAC with SHA-2 Functions as defined in [section 3.2 of RFC 7518]
///
/// [section 3.2 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.2>
#[derive(Debug)]
pub enum Hmac {
    /// HMAC using SHA-256
    Hs256,
    /// HMAC using SHA-384
    Hs384,
    /// HMAC using SHA-512
    Hs512,
}
