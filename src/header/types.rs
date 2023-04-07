mod jwe;
mod jws;

use alloc::string::ToString;

#[doc(inline)]
pub use self::{jwe::*, jws::*};
use super::{builder::Specific, Error, HeaderDeserializer};
use crate::sealed::Sealed;

/// Trait used to specify where a [`JoseHeader`](super::JoseHeader) is being
/// used. Implemented by [`Jws`] and [`Jwe`].
///
/// This trait is an implementation detailed and sealed. It is not relevant for
/// developers using this crate.
pub trait Type: Sealed {
    /// A list of parameters that are not allowed in the `crit` header.
    ///
    /// This list might grow or shrink. This is not considered a breaking
    /// change.
    fn forbidden_critical_headers() -> &'static [&'static str];
    /// Build the implementing type while preseving the [`HeaderDeserializer`]
    ///
    /// # Errors
    ///
    /// Should return an [`Error`] if deserialization fails or an invalid value
    /// is detected.
    fn from_deserializer(
        de: HeaderDeserializer,
    ) -> Result<(Self, HeaderDeserializer), (Error, HeaderDeserializer)>
    where
        Self: Sized;

    /// Implementation detail of
    /// [`JoseHeaderBuilder`](super::JoseHeaderBuilder).
    fn specific_default() -> Specific;

    /// Implementation detail of
    /// [`JoseHeaderBuilder`](super::JoseHeaderBuilder).
    fn into_specific(self) -> Specific;
}

impl Type for Jws {
    #[inline]
    fn forbidden_critical_headers() -> &'static [&'static str] {
        // <https://www.rfc-editor.org/rfc/rfc7515.html#section-9.1.2>
        // FIXME: add parameters from JWA
        &[
            "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
        ]
    }

    fn from_deserializer(
        mut de: HeaderDeserializer,
    ) -> Result<(Self, HeaderDeserializer), (Error, HeaderDeserializer)>
    where
        Self: Sized,
    {
        // "try" blocks hack
        let mut t = || {
            Ok(Self {
                algorithm: de
                    .deserialize_field("alg")
                    .transpose()?
                    .ok_or(Error::MissingHeader("alg".to_string()))?,
                payload_base64_url_encoded: de
                    .deserialize_field("b64")
                    .transpose()?
                    // `b64` must be protected
                    .map(|v| v.protected().ok_or(Error::ExpectedProtected))
                    .transpose()?,
            })
        };
        let s: Result<Jws, Error> = t();
        match s {
            Ok(v) => Ok((v, de)),
            Err(e) => Err((e, de)),
        }
    }

    fn specific_default() -> Specific {
        Specific::Jws {
            algorithm: None,
            payload_base64_url_encoded: None,
        }
    }

    fn into_specific(self) -> Specific {
        Specific::Jws {
            algorithm: Some(self.algorithm),
            payload_base64_url_encoded: self.payload_base64_url_encoded,
        }
    }
}

impl Type for Jwe {
    #[inline]
    fn forbidden_critical_headers() -> &'static [&'static str] {
        // <https://www.rfc-editor.org/rfc/rfc7516.html#section-10.1.1>
        // FIXME: add parameters from JWA
        &[
            "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ",
            "cty", "crit",
        ]
    }

    fn from_deserializer(
        _de: HeaderDeserializer,
    ) -> Result<(Self, HeaderDeserializer), (Error, HeaderDeserializer)>
    where
        Self: Sized,
    {
        todo!()
    }

    fn specific_default() -> Specific {
        Specific::Jwe {
            algorithm: None,
            content_encryption_algorithm: None,
        }
    }

    fn into_specific(self) -> Specific {
        Specific::Jwe {
            algorithm: Some(self.algorithm),
            content_encryption_algorithm: Some(self.content_encryption_algorithm),
        }
    }
}
