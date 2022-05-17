use alloc::string::String;

/// An Elliptic Curve Key as defined in [section 6.2 of RFC 7518]
///
/// [section 6.2 of RFC7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2>
#[derive(Debug)]
pub enum EllipticCurveKey {
    Public(EllipticCurvePublicKey),
    Private(EllipticCurvePrivateKey),
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1>
#[derive(Debug)]
pub struct EllipticCurvePublicKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    // FIXME: this probably should be an enum and cover <https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve>
    crv: String,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2>
    x: usize,
    // <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3>
    // y for P-256, -384 and -521
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2>
#[derive(Debug)]
pub struct EllipticCurvePrivateKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    // FIXME: this probably should be an enum and cover <https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve>
    crv: String,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2>
    x: usize,
    // <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3>
    // y for P-256, -384 and -521
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1>
    d: usize,
}
