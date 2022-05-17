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
    crv: EllipticCurve,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2>
    x: usize,
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2>
#[derive(Debug)]
pub struct EllipticCurvePrivateKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    crv: EllipticCurve,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2>
    x: usize,
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1>
    d: usize,
}

/// An enum to represent elliptic curve keys from the [JSON Web Key
/// Elliptic Curve registry]
///
/// [JSON Web Key Elliptic Curve registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve>
// FIXME: P-Curves an secp256k1 match key type `EC` the rest matches `OKP`
// consider abstracting `EC` and `OKP` matchers more
#[derive(Debug)]
pub enum EllipticCurve {
    /// P-Curve
    P(PCurve),
    /// Ed25519 signature algorithm key as defined in [section 3.1 of RFC
    /// 8037]
    ///
    /// [section 3.1 of RFC 8037]: <https://datatracker.ietf.org/doc/html/rfc8037#section-3.1>
    Ed25519,
    /// Ed448 signature algorithm key as defined in [section 3.1 of RFC
    /// 8037]
    ///
    /// [section 3.1 of RFC 8037]: <https://datatracker.ietf.org/doc/html/rfc8037#section-3.1>
    Ed448,
    /// X25519 function key as defined in [section 3.2 of RFC 8037]
    ///
    /// [section 3.2 of RFC 8037]: <https://datatracker.ietf.org/doc/html/rfc8037#section-3.2>
    X25519,
    /// X448 function key as defined in [section 3.2 of RFC 8037]
    ///
    /// [section 3.2 of RFC 8037]: <https://datatracker.ietf.org/doc/html/rfc8037#section-3.2>
    X448,
    /// SECG secp256k1 curve as defined in [section 3.1 of RFC 8812]
    ///
    /// [section 3.1 of RFC 8812]: <https://datatracker.ietf.org/doc/html/rfc8812#section-3.1>
    Secp256k1,
}

/// P-Curves as defined in [section 6.2.1.1 of RFC 7518]
///
/// [section 6.2.1.1 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
#[derive(Debug)]
pub struct PCurve {
    /// P-Curve have an extra `y` parameter as defind in [section 6.2.1.3]
    ///
    /// [section 6.2.1.3]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3>
    y: usize,
    /// The actual P-Curve used
    variant: PCurveVariant,
}

#[derive(Debug)]
/// The different variants of the P-Curves
pub enum PCurveVariant {
    /// P-256 Curve as defined in [section 6.2.1.1 of RFC 7518]
    ///
    /// [section 6.2.1.1 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    P256,
    /// P-384 Curve as defined in [section 6.2.1.1 of RFC 7518]
    ///
    /// [section 6.2.1.1 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    P384,
    /// P-521 Curve as defined in [section 6.2.1.1 of RFC 7518]
    ///
    /// [section 6.2.1.1 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1>
    P521,
}
