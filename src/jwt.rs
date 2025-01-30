//! JsonWebToken (JWT) implementation
//!
//! JWTs are the most common use of JOSE.

use alloc::string::String;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    format::{self, Compact},
    jws::{FromRawPayload, IntoPayload, JsonWebSignatureBuilder, PayloadData, PayloadKind},
    Base64UrlString, JsonWebSignature, Jws,
};

/// A JSON Web Token (JWT) as defined in [RFC 7519].
///
/// Since a JWT is only allowed to be serialized in the compact format, the
/// `F` type parameter is fixed to [`Compact`] in this type
/// alias.
///
/// [RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
pub type JsonWebToken<A> = JsonWebSignature<format::Compact, Claims<A>>;

impl JsonWebToken<()> {
    /// Returns a [`JsonWebSignatureBuilder`] for a [`JsonWebToken`]
    // this method is needed because of interference problems if it is named
    // builder directly.
    pub fn builder_jwt() -> JsonWebSignatureBuilder<Compact> {
        Jws::builder()
    }
}

/// The claims of a JSON Web Token (JWT) as defined in [RFC 7519].
///
/// The `A` type parameter is used to specify the type of the additional
/// parameters of the claims. If no additional parameters are required,
/// the unit type `()` can be used.
///
/// [RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Claims<A = ()> {
    /// The "iss" (issuer) claim identifies the principal that issued the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1).
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// The "sub" (subject) claim identifies the principal that is the subject
    /// of the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2).
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// The "aud" (audience) claim identifies the recipients that the JWT is
    /// intended for.
    ///
    /// As defined in [RFC 7519 Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3).
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// The "exp" (expiration time) claim identifies the expiration time on or
    /// after which the JWT MUST NOT be accepted for processing.
    ///
    /// As defined in [RFC 7519 Section 4.1.4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4).
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<u64>,

    /// The "nbf" (not before) claim identifies the time before which the JWT
    /// MUST NOT be accepted for processing.
    ///
    /// As defined in [RFC 7519 Section 4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5).
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,

    /// The "iat" (issued at) claim identifies the time at which the JWT was
    /// issued.
    ///
    /// As defined in [RFC 7519 Section 4.1.6](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6).
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,

    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    ///
    /// As defined in [RFC 7519 Section 4.1.7](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7).
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    /// Additional, potentially unregistered JWT claims.
    #[serde(flatten)]
    pub additional: A,
}

impl<A> IntoPayload for Claims<A>
where
    A: Serialize,
{
    type Error = serde_json::Error;

    fn into_payload(self) -> Result<PayloadKind, Self::Error> {
        let encoded = serde_json::to_vec(&self)?;
        Ok(PayloadKind::Attached(PayloadData::Standard(
            Base64UrlString::encode(encoded),
        )))
    }
}

/// Error returned by [`FromRawPayload`] implementation of [`Claims`]
#[derive(Debug, thiserror_no_std::Error)]
#[non_exhaustive]
pub enum ClaimsDecodeError {
    /// [`Claims`] does not support this operation.
    #[error("Operation not supported.")]
    OperationUnsupported,
    /// Error while deserializing underlying Json
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl<A> FromRawPayload for Claims<A>
where
    A: DeserializeOwned,
{
    type Context = ();
    type Error = ClaimsDecodeError;

    fn from_attached(_: &Self::Context, payload: PayloadData) -> Result<Self, Self::Error> {
        let data = match payload {
            PayloadData::Standard(data) => data.decode(),
        };
        let claims: Claims<A> = serde_json::from_slice(&data)?;
        Ok(claims)
    }

    /// Detached is not supported with [`JsonWebToken`]
    ///
    /// # Returns
    ///
    /// Always returns [`ClaimsDecodeError::OperationUnsupported`]
    fn from_detached<F, T>(
        _: &Self::Context,
        _: &crate::JoseHeader<F, T>,
    ) -> Result<(Self, PayloadData), Self::Error> {
        Err(ClaimsDecodeError::OperationUnsupported)
    }

    /// Detached is not supported with [`JsonWebToken`]
    ///
    /// # Returns
    ///
    /// Always returns [`ClaimsDecodeError::OperationUnsupported`]
    fn from_detached_many<F, T>(
        _: &Self::Context,
        _: &[crate::JoseHeader<F, T>],
    ) -> Result<(Self, PayloadData), Self::Error> {
        Err(ClaimsDecodeError::OperationUnsupported)
    }
}
