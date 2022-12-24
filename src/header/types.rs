mod jwe;
mod jws;

use alloc::string::ToString;

#[doc(inline)]
pub use self::{jwe::*, jws::*};
use super::{Error, HeaderDeserializer};
use crate::sealed::Sealed;

pub trait Type: Sealed {
    fn forbidden_critical_headers() -> &'static [&'static str];
    fn from_deserializer(
        de: HeaderDeserializer,
    ) -> Result<(Self, HeaderDeserializer), (Error, HeaderDeserializer)>
    where
        Self: Sized;
}

impl Type for Jws {
    #[inline]
    fn forbidden_critical_headers() -> &'static [&'static str] {
        // <https://www.rfc-editor.org/rfc/rfc7515.html#section-9.1.2>
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
}

impl Type for Jwe {
    #[inline]
    fn forbidden_critical_headers() -> &'static [&'static str] {
        // <https://www.rfc-editor.org/rfc/rfc7516.html#section-10.1.1>
        &[
            "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ",
            "cty", "crit",
        ]
    }

    fn from_deserializer(
        de: HeaderDeserializer,
    ) -> Result<(Self, HeaderDeserializer), (Error, HeaderDeserializer)>
    where
        Self: Sized,
    {
        todo!()
    }
}
