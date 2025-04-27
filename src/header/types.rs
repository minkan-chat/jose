mod jwe;
mod jws;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};

use serde_json::Value;

#[doc(inline)]
pub use self::{jwe::*, jws::*};
use super::{builder::Specific, Error, HeaderDeserializer, HeaderValue};
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

    /// Convert fields into a Map that can be used for serialization
    ///
    /// # Errors
    ///
    /// May return an error if the conversion to [`Value`] fails.
    fn into_map(self) -> Result<BTreeMap<String, HeaderValue<Value>>, Error>;
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

    fn into_map(self) -> Result<BTreeMap<String, HeaderValue<Value>>, Error> {
        let mut map = BTreeMap::new();
        map.insert(
            "alg".to_string(),
            self.algorithm.map(serde_json::to_value).transpose()?,
        );

        // if explictly set to true, set it even tho true is the default
        if let Some(b64) = self.payload_base64_url_encoded {
            map.insert(
                "b64".to_string(),
                HeaderValue::Protected(serde_json::to_value(b64)?),
            );
        }

        Ok(map)
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
                content_encryption_algorithm: de
                    .deserialize_field("enc")
                    .transpose()?
                    .ok_or(Error::MissingHeader("enc".to_string()))?,
            })
        };
        let s: Result<Jwe, Error> = t();
        match s {
            Ok(v) => Ok((v, de)),
            Err(e) => Err((e, de)),
        }
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

    fn into_map(self) -> Result<BTreeMap<String, HeaderValue<Value>>, Error> {
        Ok([
            (
                "alg".to_string(),
                self.algorithm.map(serde_json::to_value).transpose()?,
            ),
            (
                "enc".to_string(),
                self.content_encryption_algorithm
                    .map(serde_json::to_value)
                    .transpose()?,
            ),
        ]
        .into_iter()
        .collect())
    }
}
