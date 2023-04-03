use crate::{header::HeaderValue, jwa::JsonWebSigningAlgorithm, sealed::Sealed};

/// Parameters specific to Json Web Signatures
#[derive(Debug)]
#[non_exhaustive]
pub struct Jws {
    // `alg` parameter
    pub(crate) algorithm: HeaderValue<JsonWebSigningAlgorithm>,
    /// `b64` parameter as defined by RFC 7797. This parameter is optional and
    /// it's default value is `true`.
    ///
    /// If this value is `false`, the payload of the JWS is not base64 urlsafe
    /// encoded. This can work for simple stuff like a hex string, but will
    /// often cause parsing errors. Use of this option makes sense if the
    /// payload of a JWS is detached.
    ///
    /// Note: In a JsonWebToken, this value MUST always be true. Therefore, the
    /// payload MUST NOT use the unencoded payload option.
    ///
    /// Note: This header MUST be integrity protected.
    pub(crate) payload_base64_url_encoded: Option<bool>,
}

impl Sealed for Jws {}
