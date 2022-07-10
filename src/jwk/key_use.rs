use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

/// This enum represents possible key usage (`use`) parameter as
/// defined in [Section 4.2 of RFC 7517]. All possible values are registered in
/// the [IANA `JSON Web Key Use` registry].
///
/// [Section 4.2 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
/// [IANA `JSON Web Key Use` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-use>
#[non_exhaustive]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum KeyUsage {
    /// The `sig` (signature) value
    Signing,
    /// The `enc` (encryption) value
    Encryption,
    /// Some other case-sensitive [`String`] that did not match any of the
    /// publicly known variants
    Other(String),
}

impl Serialize for KeyUsage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Signing => "sig",
            Self::Encryption => "enc",
            Self::Other(s) => s,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyUsage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = <&str as Deserialize>::deserialize(deserializer)?;
        Ok(match val {
            "sig" => Self::Signing,
            "enc" => Self::Encryption,
            _ => Self::Other(val.to_string()),
        })
    }
}
