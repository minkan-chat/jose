use crate::{jwe::JsonWebEncryption, jws::JsonWebSignature};

/// A JSON Web Token (JWT) as defined in [RFC 7519]
///
/// [RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
#[derive(Debug)]
pub enum JsonWebToken {
    /// A JSON Web Token that contains a JSON Web Encryption (JWE) as defined in
    /// [RFC 7516]
    ///
    /// [RFC 7516]: <https://datatracker.ietf.org/doc/html/rfc7516>
    JsonWebEncryption(JsonWebEncryption),
    /// A JSON Web Token that contains a JSON Web Signature (JWS) as defined in
    /// [RFC 7515]
    ///
    /// [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>
    JsonWebSignature(JsonWebSignature<()>),
}
