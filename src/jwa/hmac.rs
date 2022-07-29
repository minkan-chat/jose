/// HMAC with SHA-2 Functions as defined in [section 3.2 of RFC 7518]
///
/// [section 3.2 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hmac {
    /// HMAC using SHA-256
    Hs256,
    /// HMAC using SHA-384
    Hs384,
    /// HMAC using SHA-512
    Hs512,
}

impl From<Hmac> for super::JsonWebSigningAlgorithm {
    fn from(x: Hmac) -> Self {
        Self::Hmac(x)
    }
}

impl From<Hmac> for super::JsonWebAlgorithm {
    fn from(x: Hmac) -> Self {
        Self::Signing(super::JsonWebSigningAlgorithm::Hmac(x))
    }
}
