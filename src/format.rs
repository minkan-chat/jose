//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! Currently, the only two formats are [`Compact`] and [`Json`].

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The compact representation is essentially a list of Base64
/// strings that are separated by `.`.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Compact {
    parts: Vec<String>,
}

impl Compact {
    /// Creates an empty compact representation that can be filled
    /// with parts.
    pub(crate) fn new() -> Self {
        Compact {
            parts: Vec::with_capacity(3),
        }
    }

    /// Pushes the given part into this compact representation,
    /// by encoding the given bytes to Base64Url format.
    pub(crate) fn push(&mut self, part: impl AsRef<[u8]>) {
        let encoded = Base64UrlUnpadded::encode_string(part.as_ref());
        self.parts.push(encoded);
    }
}

/// Error type indicating that one part of the compact
/// representation was an invalid Base64Url string.
#[derive(Debug, Clone, Copy)]
pub struct NoBase64UrlString;

impl FromStr for Compact {
    type Err = NoBase64UrlString;

    /// Verifies if every part of the string is valid base64url format
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s
            .split('.')
            .map(|s| {
                if s.as_bytes().iter().all(|c| {
                    (b'A'..b'Z').contains(c)
                        || (b'a'..b'z').contains(c)
                        || (b'0'..b'9').contains(c)
                        || *c == b'_'
                        || *c == b'-'
                }) {
                    Ok(s.to_string())
                } else {
                    Err(NoBase64UrlString)
                }
            })
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

/// The json serialization format that is a wrapper around
/// a generic json value and that can be deserialized into
/// any serilizable type.
///
/// # Example
///
/// ```
/// # use jose::format::Json;
/// # use std::str::FromStr;
/// # use serde_json::json;
/// # fn main() {
/// let json = r#"{"foo":"bar"}"#;
/// let expected = json!({ "foo": "bar" });
/// let value = Json::from_str(json).unwrap();
///
/// assert_eq!(value.clone().into_inner(), expected);
/// assert_eq!(value.to_string(), json.to_string());
/// # }
/// ```
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Json {
    value: Value,
}

impl Json {
    /// Turns this Json wrapper into it's generic underlying Value.
    pub fn into_inner(self) -> Value {
        self.value
    }
}

impl FromStr for Json {
    type Err = serde_json::Error;

    /// The from_str implementation will parse the supplied
    /// string as JSON.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = serde_json::from_str::<Value>(s)?;
        Ok(Self { value })
    }
}

impl fmt::Display for Json {
    /// The display implementation will format this value
    /// as compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}
