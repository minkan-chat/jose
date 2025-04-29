//! Helpers for base64 urlsafe encoded stuff

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{fmt, ops::Deref, str::FromStr};

use base64ct::{Base64UrlUnpadded, Encoding};
use secrecy::{ExposeSecret as _, SecretSlice};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Error type indicating that one part of the CompactJws
/// representation was an invalid Base64Url string.
#[derive(Debug, Clone, Copy, Error)]
#[error("the string is not a valid Base64Url representation")]
pub struct NoBase64UrlString;

/// A wrapper around a [`String`] that guarantees that the inner string is a
/// valid Base64Url string.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Default)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Base64UrlString(String);

impl<'de> Deserialize<'de> for Base64UrlString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = String::deserialize(deserializer)?;
        Base64UrlString::from_str(&inner).map_err(D::Error::custom)
    }
}

impl fmt::Display for Base64UrlString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for Base64UrlString {
    type Err = NoBase64UrlString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // it is an expensive check.. yes
        base64ct::Base64UrlUnpadded::decode_vec(s)
            .map(|_| Self(s.to_owned()))
            .map_err(|_| NoBase64UrlString)
    }
}

impl Base64UrlString {
    /// Creates a new, empty Base64Url string.
    #[inline]
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Encode the given bytes using Base64Url format.
    #[inline]
    pub fn encode(x: impl AsRef<[u8]>) -> Self {
        Base64UrlString(Base64UrlUnpadded::encode_string(x.as_ref()))
    }

    /// Decodes this Base64Url string into it's raw byte representation.
    #[inline]
    pub fn decode(&self) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(&self.0)
            .expect("Base64UrlString is guaranteed to be a valid base64 string")
    }

    /// Return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Base64UrlString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Zeroize)]
pub(crate) struct Base64UrlBytes(pub(crate) Vec<u8>);

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(&self.0);
        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;

        let decoded = Base64UrlUnpadded::decode_vec(&encoded)
            .map_err(|_| D::Error::custom("encountered invalid Base64Url string"))?;

        Ok(Self(decoded))
    }
}

#[derive(Debug, Clone, Zeroize)]
pub(crate) struct SecretBase64UrlBytes(pub(crate) SecretSlice<u8>);

impl Serialize for SecretBase64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = self.0.expose_secret();
        let encoded = Zeroizing::new(Base64UrlUnpadded::encode_string(data));

        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretBase64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);

        let decoded = Base64UrlUnpadded::decode_vec(&encoded)
            .map_err(|_| D::Error::custom("encountered invalid Base64Url string"))?;

        Ok(Self(SecretSlice::from(decoded)))
    }
}

// TODO: test for correct length check and base64url parsing
#[cfg(test)]
mod tests {}
