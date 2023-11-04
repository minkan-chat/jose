use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::{format, JsonWebSignature};

/// A JSON Web Token (JWT) as defined in [RFC 7519].
///
/// Since a JWT is only allowed to be serialized in the compact format, the
/// `F` type parameter is fixed to [`Compact`](format::Compact) in this type
/// alias.
///
/// [RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
pub type JsonWebToken<A> = JsonWebSignature<format::Compact, Claims<A>>;

/// The claims of a JSON Web Token (JWT) as defined in [RFC 7519].
///
/// The `A` type parameter is used to specify the type of the additional
/// parameters of the claims. If no additional parameters are required,
/// the unit type `()` can be used.
///
/// [RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims<A = ()> {
    /// The "iss" (issuer) claim identifies the principal that issued the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1).
    #[serde(rename = "iss")]
    pub issuer: Option<String>,

    /// The "sub" (subject) claim identifies the principal that is the subject
    /// of the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2).
    #[serde(rename = "sub")]
    pub subject: Option<String>,

    /// The "aud" (audience) claim identifies the recipients that the JWT is
    /// intended for.
    ///
    /// As defined in [RFC 7519 Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3).
    #[serde(rename = "aud")]
    pub audience: Option<String>,

    /// The "exp" (expiration time) claim identifies the expiration time on or
    /// after which the JWT MUST NOT be accepted for processing.
    ///
    /// As defined in [RFC 7519 Section 4.1.4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4).
    #[serde(rename = "exp")]
    pub expiration: Option<u64>,

    /// The "nbf" (not before) claim identifies the time before which the JWT
    /// MUST NOT be accepted for processing.
    ///
    /// As defined in [RFC 7519 Section 4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5).
    #[serde(rename = "nbf")]
    pub not_before: Option<u64>,

    /// The "iat" (issued at) claim identifies the time at which the JWT was
    /// issued.
    ///
    /// As defined in [RFC 7519 Section 4.1.6](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6).
    #[serde(rename = "iat")]
    pub issued_at: Option<u64>,

    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.7](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7).
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,

    /// Additional, potentially unregistered JWT claims.
    #[serde(flatten)]
    pub additional: A,
}
