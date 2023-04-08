use core::ops::Deref;

use crate::sealed::Sealed;

/// Some value `T` in either the protected or unprotected header.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeaderValue<T> {
    /// `T` is in the `protected` header parameter and integrity protected.
    Protected(T),
    /// `T` is in the unprotected `header` parameter and NOT integrity
    /// protected.
    Unprotected(T),
}

impl<T> Sealed for HeaderValue<T> {}

impl<T> HeaderValue<T> {
    /// Convert from `&HeaderValue<T>` to `HeaderValue<&T>`.
    ///
    /// Works like [`Option::as_ref`]
    pub fn as_ref(&self) -> HeaderValue<&'_ T> {
        match self {
            HeaderValue::Protected(v) => HeaderValue::Protected(v),
            HeaderValue::Unprotected(v) => HeaderValue::Unprotected(v),
        }
    }

    /// Converts from `&HeaderValue<T>` to `HeaderValue<&T::Target>`.
    ///
    /// Works like [`Option::as_deref`]
    pub fn as_deref(&self) -> HeaderValue<&T::Target>
    where
        T: Deref,
    {
        match self.as_ref() {
            HeaderValue::Protected(t) => HeaderValue::Protected(t.deref()),
            HeaderValue::Unprotected(t) => HeaderValue::Unprotected(t.deref()),
        }
    }

    /// Maps an `HeaderValue<T>` to `HeaderValue<U>` by applying a function to a
    /// contained value.
    pub fn map<U, F>(self, f: F) -> HeaderValue<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            HeaderValue::Protected(t) => HeaderValue::Protected(f(t)),
            HeaderValue::Unprotected(t) => HeaderValue::Unprotected(f(t)),
        }
    }

    /// Returns [`Some`] if `T` is in the `protected` parameter.
    pub fn protected(self) -> Option<T> {
        match self {
            Self::Protected(p) => Some(p),
            _ => None,
        }
    }

    /// Returns [`Some`] if `T` is in the unprotected `header` parameter.
    pub fn unprotected(self) -> Option<T> {
        match self {
            Self::Unprotected(u) => Some(u),
            _ => None,
        }
    }

    /// Returns the inner type `T` discarding the information about where `T` is
    /// stored.
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

impl<T, E> HeaderValue<Result<T, E>> {
    /// Transpose a [`HeaderValue<Result<T, E>>] into
    /// [`Result<HeaderValue<`T`>, E>`]
    ///
    /// # Errors
    ///
    /// Returns an error if the inner [`Result`] contains an error.
    pub fn transpose(self) -> Result<HeaderValue<T>, E> {
        Ok(match self {
            Self::Protected(p) => HeaderValue::Protected(p?),
            Self::Unprotected(u) => HeaderValue::Unprotected(u?),
        })
    }
}
