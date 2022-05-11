use alloc::{string::String, vec::Vec};
use core::{borrow::Borrow, fmt, ops::Deref};

const VALID_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Wrapper around a string that requires to be valid base64 url encoded.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
#[repr(transparent)]
pub struct Base64String(String);

impl Base64String {
    /// Turns this Base64 string into the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Creates a new `Base64String` by checking if the given string
    /// is valid base64.
    ///
    /// Returns `None` if the string contains invalid characters.
    pub fn from_string(s: String) -> Option<Self> {
        if s.chars().all(|c| VALID_CHARS.contains(c)) {
            Some(Self(s))
        } else {
            None
        }
    }

    /// Encode the given bytes into a Base64 string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> Base64String {
        Self(base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
    }

    /// Decodes this string into the raw bytes.
    pub fn decode(self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode_config(&self.0, base64::URL_SAFE_NO_PAD)
    }
}

impl Deref for Base64String {
    type Target = str;

    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl Borrow<str> for Base64String {
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Base64String> for String {
    fn from(x: Base64String) -> Self {
        x.0
    }
}

impl fmt::Display for Base64String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
