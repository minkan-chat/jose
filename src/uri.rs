use alloc::string::String;
use core::{fmt, ops::Deref};

use serde::{Deserialize, Serialize};

/// A serializable URI type implemented using [`serde`] and [`fluent_uri`].
///
/// This is a thing wrapper around a [`fluent_uri::Uri<String>`] that implements
/// [`Serialize`] and [`Deserialize`].
#[derive(Debug, Clone, Default)]
pub struct Uri(fluent_uri::Uri<String>);

impl Uri {
    /// Borrows this URI.
    pub fn borrow(&self) -> BorrowedUri<'_> {
        BorrowedUri(self.0.borrow())
    }

    /// Turns this URI into the underlying [`fluent_uri::Uri<String>`].
    pub fn into_inner(self) -> fluent_uri::Uri<String> {
        self.0
    }
}

impl PartialEq for Uri {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str().eq(other.0.as_str())
    }
}
impl Eq for Uri {}

impl Deref for Uri {
    type Target = fluent_uri::Uri<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<fluent_uri::Uri<String>> for Uri {
    fn from(uri: fluent_uri::Uri<String>) -> Self {
        Self(uri)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let uri = String::deserialize(deserializer)?;

        Ok(Uri(
            fluent_uri::Uri::parse_from(uri).map_err(|(_, e)| serde::de::Error::custom(e))?
        ))
    }
}

/// A borrowed version of the [`Uri`].
///
/// This is a thing wrapper around a [`fluent_uri::Uri<&str>`] that implements
/// [`Serialize`].
#[derive(Debug)]
pub struct BorrowedUri<'s>(&'s fluent_uri::Uri<&'s str>);

impl BorrowedUri<'_> {
    /// Turns this borrowed URI into an owned [`Uri`].
    pub fn to_owned(&self) -> Uri {
        Uri(self.0.to_owned())
    }
}

impl<'s> Deref for BorrowedUri<'s> {
    type Target = fluent_uri::Uri<&'s str>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl fmt::Display for BorrowedUri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (*self.0).fmt(f)
    }
}

impl Serialize for BorrowedUri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl PartialEq for BorrowedUri<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str().eq(other.0.as_str())
    }
}
impl Eq for BorrowedUri<'_> {}
