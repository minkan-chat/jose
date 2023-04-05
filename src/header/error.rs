use alloc::string::String;

/// Errors that may occur while working [`JoseHeader`](super::JoseHeader)
#[derive(Debug, thiserror_no_std::Error)]
#[non_exhaustive]
pub enum Error {
    /// Found a header parameter that must be protected in the unprotected
    /// `header` parameter
    ExpectedProtected,
    /// The `protected` and (unprotected) `header` parameter share members with
    /// the same name
    NotDisjoint,
    /// Both the `protected` and (unprotected) `header` members in a JWS or JWE
    /// are empty.
    NoHeader,
    /// The `protected` or the (unprotected) `header` member is present but
    /// contains no members (it is an empty object `{}`)
    EmptyHeader,
    /// Found a header parameter name that is forbidden as per [section 4.1.11
    /// of RFC 7515]
    ///
    /// [section 4.1.11 of RFC 7515]: <https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11>
    ForbiddenHeader(String),
    /// A REQUIRED header is missing (e.g. the `alg` header)
    MissingHeader(String),
    /// The `crit` header is present but an empty list (`[]`)
    EmptyCriticalHeaders,
    /// A JSON deserialization error, see [`serde_json::Error`] for details.
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}
