#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaKey {
    Public(RsaPublicKey),
    Private(RsaPrivateKey),
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1>
    n: usize,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2>
    e: usize,
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPrivateKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1>
    n: usize,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2>
    e: usize,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1>
    d: usize,
    // FIXME: there are more parameters which are a bit more complicated, see
    // <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2>
}
