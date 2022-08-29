//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! Currently, the only two formats are [`Compact`] and [`JsonFlattened`].

use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{base64_url::NoBase64UrlString, jws::Unverified, sealed::Sealed, Base64UrlString};

/// Conversion of a raw input format (e.g., [`Compact`], [`JsonFlattened`], etc)
/// to this type.
pub trait FromFormat<F>: Sized + Sealed {
    /// The error that can occurr while parsing `Self` from the input.
    type Error;

    /// Parse the input into a new [unverified](Unverified) instance of `Self`.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// this type.
    fn from_format(input: F) -> Result<Unverified<Self>, Self::Error>;
}

/// Turns `self` into a format.
///
/// This trait can be ignored for any user of the crate as it is
/// only used for internal workings of the crate.
pub trait IntoFormat<F>: Sealed {
    #[doc(hidden)]
    fn into_format(self) -> F;
}

/// Appends a signature to a format.
///
/// This trait can be ignored for any user of the crate as it is
/// only used for internal workings of the crate.
pub trait AppendSignature: Sealed {
    #[doc(hidden)]
    fn append_signature(&mut self, sig: &[u8]);
}

impl Sealed for Compact {}
impl AppendSignature for Compact {
    fn append_signature(&mut self, sig: &[u8]) {
        self.push(sig);
    }
}

impl Sealed for JsonFlattened {}
impl AppendSignature for JsonFlattened {
    fn append_signature(&mut self, sig: &[u8]) {
        let sig = Base64UrlUnpadded::encode_string(sig);
        if !sig.is_empty() {
            self.value["signature"] = Value::String(sig);
        }
    }
}

/// The compact representation is essentially a list of Base64Url
/// strings that are separated by `.`.
// FIXME: refactor `Compact` struct to not only contain Base64Url strings
// since there is the option for an unencoded payload
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Compact {
    parts: Vec<Base64UrlString>,
}

impl Compact {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Compact {
            parts: Vec::with_capacity(cap),
        }
    }

    pub(crate) fn part(&self, idx: usize) -> Option<&Base64UrlString> {
        self.parts.get(idx)
    }

    pub(crate) fn len(&self) -> usize {
        self.parts.len()
    }

    pub(crate) fn push(&mut self, part: impl AsRef<[u8]>) {
        self.parts.push(Base64UrlString::encode(part));
    }

    pub(crate) fn push_base64url(&mut self, raw: Base64UrlString) {
        self.parts.push(raw);
    }
}

impl FromStr for Compact {
    type Err = NoBase64UrlString;

    /// Verifies if every part of the string is valid base64url format
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s
            .split('.')
            .map(|s| Base64UrlString::from_str(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { parts })
    }
}

impl fmt::Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.parts.len();

        for (idx, part) in self.parts.iter().enumerate() {
            fmt::Display::fmt(&part, f)?;

            if idx != len - 1 {
                f.write_str(".")?;
            }
        }

        Ok(())
    }
}

/// The flattened json serialization format that is a wrapper around
/// a generic json value and that can be deserialized into
/// any serilizable type.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct JsonFlattened {
    pub(crate) value: Value,
}

impl JsonFlattened {
    /// Turns this Json wrapper into it's generic underlying Value.
    pub fn into_inner(self) -> Value {
        self.value
    }
}

impl FromStr for JsonFlattened {
    type Err = serde_json::Error;

    /// The from_str implementation will parse the supplied
    /// string as JSON.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = serde_json::from_str::<Value>(s)?;
        Ok(Self { value })
    }
}

impl fmt::Display for JsonFlattened {
    /// The display implementation will format this value
    /// as compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}
