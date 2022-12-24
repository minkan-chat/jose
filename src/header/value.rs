use core::ops::Deref;

use crate::sealed::Sealed;

#[derive(Debug)]
pub enum HeaderValue<T> {
    Protected(T),
    Unprotected(T),
}

impl<T> Sealed for HeaderValue<T> {}

impl<T> HeaderValue<T> {
    pub fn as_ref(&self) -> HeaderValue<&'_ T> {
        match self {
            HeaderValue::Protected(v) => HeaderValue::Protected(v),
            HeaderValue::Unprotected(v) => HeaderValue::Unprotected(v),
        }
    }

    pub fn as_deref(&self) -> HeaderValue<&T::Target>
    where
        T: Deref,
    {
        match self.as_ref() {
            HeaderValue::Protected(t) => HeaderValue::Protected(t.deref()),
            HeaderValue::Unprotected(t) => HeaderValue::Unprotected(t.deref()),
        }
    }

    pub fn map<U, F>(self, f: F) -> HeaderValue<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            HeaderValue::Protected(t) => HeaderValue::Protected(f(t)),
            HeaderValue::Unprotected(t) => HeaderValue::Unprotected(f(t)),
        }
    }

    pub fn protected(self) -> Option<T> {
        match self {
            Self::Protected(p) => Some(p),
            _ => None,
        }
    }

    pub fn unprotected(self) -> Option<T> {
        match self {
            Self::Unprotected(u) => Some(u),
            _ => None,
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            Self::Protected(t) => t,
            Self::Unprotected(t) => t,
        }
    }
}

impl<T> HeaderValue<Option<T>> {
    /// Transpose a [`HeaderValue<Option<T>>`] into [`Option<HeaderValue<T>>`]
    pub fn transpose(self) -> Option<HeaderValue<T>> {
        Some(match self {
            HeaderValue::Protected(p) => HeaderValue::Protected(p?),
            HeaderValue::Unprotected(u) => HeaderValue::Unprotected(u?),
        })
    }
}
