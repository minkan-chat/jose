use alloc::string::String;

use serde::{Deserialize, Serialize};

/// This enum represents the key operations (`key_ops`) parameter as defined in
/// [Section 4.3 of RFC 7517]. All possible values are registered in the [IANA
/// `JSON Web Key Operations` registry].
///
/// This enum SHOULD NOT be used together with the [`KeyUsage`](super::KeyUsage)
/// enum. If they are both present, their information MUST be consistent.
///
/// [Section 4.3 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
/// [IANA `JSON Web Key Operations` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations>
#[non_exhaustive]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum KeyOperation {
    /// This key may compute digital signatures or MACs
    Sign,
    /// This key may verify digital signatures or MACs
    Verify,
    /// This key may encrypt content
    Encrypt,
    /// This key may decrypt content and validate decryption, if applicable
    Decrypt,
    /// This key may encrypt a key
    WrapKey,
    /// This key may decrypt a key and validate the decryption, if applicable
    UnwrapKey,
    /// This key may derive a key
    DeriveKey,
    /// This key may derive bits not to be used as a key
    DeriveBits,
    /// Some other case-sensitive [`String`] that did not match any of the
    /// publicly known key operations
    Other(String),
}

impl Serialize for KeyOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
            Self::Other(s) => s,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = <alloc::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        Ok(match &*val {
            "sign" => Self::Sign,
            "verify" => Self::Verify,
            "encrypt" => Self::Encrypt,
            "decrypt" => Self::Decrypt,
            "wrapKey" => Self::WrapKey,
            "unwrapKey" => Self::UnwrapKey,
            "deriveKey" => Self::DeriveKey,
            "deriveBits" => Self::DeriveBits,
            _ => Self::Other(val.into_owned()),
        })
    }
}
