use alloc::{
    borrow::{Cow, ToOwned},
    string::{String, ToString},
};
use core::{fmt, ops::Deref};

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};

#[derive(PartialEq, Eq)]
pub(crate) struct Borrowable<'a, T: ?Sized + ToOwned>(Cow<'a, T>);

impl<'a, T: ?Sized + ToOwned> Deref for Borrowable<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, 'de: 'a> Deserialize<'de> for Borrowable<'a, str> {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = Borrowable<'de, str>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an owned or borrowed string")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Borrowable(Cow::Borrowed(v)))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Borrowable(Cow::Owned(v.to_string())))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Borrowable(Cow::Owned(v)))
            }
        }

        de.deserialize_str(StrVisitor)
    }
}
