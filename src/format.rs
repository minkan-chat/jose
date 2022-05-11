//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! Currently, the only two formats are [`Compact`] and [`Json`].

use alloc::{string::ToString, vec::Vec};
use core::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Base64String;

/// Used to convert any type into the specified format.
pub trait Encode<F> {
    /// The type returned when an error occurred while
    /// encoding `self`.
    type Error;

    /// Performs the encode operation.
    fn encode(self) -> Result<F, Self::Error>;
}

/// Used to parse a [`Compact`] or [`Json`] representation
/// into a concrete type.
pub trait Decode<F>: Sized {
    /// The type returned when an error occurred while
    /// decoding the raw representation.
    type Error;

    /// Performs the decode operation.
    fn decode(raw: F) -> Result<Self, Self::Error>;
}

/// The compact representation is essentially a list of Base64
/// strings that are separated by `.`.
///
/// # Examples
///
/// ```
/// # use jose::format::Compact;
/// # use jose::Base64String;
/// # use std::string::ToString;
/// # use std::str::FromStr;
/// # fn main() {
/// let mut c = Compact::new();
///
/// c.push(Base64String::from_string("abc".to_string()).unwrap());
/// c.push(Base64String::from_string("def".to_string()).unwrap());
/// c.push(Base64String::from_string("ghi".to_string()).unwrap());
///
/// let s = c.to_string();
/// assert_eq!(s.as_str(), "abc.def.ghi");
///
/// let c2 = Compact::from_str("abc.def.ghi").unwrap();
/// assert_eq!(c, c2);
/// # }
/// ```
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Compact {
    parts: Vec<Base64String>,
}

impl Compact {
    /// Creates an empty compact representation that can be filled
    /// with parts.
    pub fn new() -> Self {
        Compact {
            parts: Vec::with_capacity(3),
        }
    }

    /// Pushes the given part into this compact representation.
    pub fn push(&mut self, part: Base64String) {
        self.parts.push(part);
    }
}

impl FromStr for Compact {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s
            .split('.')
            .map(|s| Base64String::from_string(s.to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or(())?;
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
