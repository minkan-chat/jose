use core::ops::Deref;

use sealed::NotFoundError;

use crate::sealed::Sealed;

pub(crate) mod sealed {
    pub trait NotFoundError {
        fn not_found() -> Self;
    }
}
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
pub trait HeaderSecurity: Sealed {
    type Output<T>: NotFoundError;

    fn from_value<T>(value: HeaderValue<T>) -> Self::Output<T>;
}

/// Marker for protected header parameters
#[derive(Debug)]
#[non_exhaustive]
pub struct Protected;
impl Sealed for Protected {}
impl HeaderSecurity for Protected {
    type Output<T> = Result<T, Error>;

    fn from_value<T>(value: HeaderValue<T>) -> Self::Output<T> {
        match value {
            HeaderValue::Protected(p) => Ok(p),
            _ => Err(Error::InvalidHeader),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Unprotected;
impl Sealed for Unprotected {}
impl HeaderSecurity for Unprotected {
    type Output<T> = Result<T, Error>;

    fn from_value<T>(value: HeaderValue<T>) -> Self::Output<T> {
        match value {
            HeaderValue::Unprotected(p) => Ok(p),
            _ => Err(Error::InvalidHeader),
        }
    }
}

#[derive(Debug, thiserror_no_std::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("the header parameter exists but does not match the requested security level")]
    InvalidHeader,
    #[error("the header parameter does not exist")]
    NotFound,
}

impl Sealed for Error {}
impl NotFoundError for Error {
    fn not_found() -> Self {
        Self::NotFound
    }
}
impl<T, E> NotFoundError for Result<T, E>
where
    E: NotFoundError,
{
    fn not_found() -> Self {
        Err(E::not_found())
    }
}
