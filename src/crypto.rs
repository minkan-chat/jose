//! Cryptographic primitives.
//!
//! This module contains all primitives required for the JOSE RFCs. It abstracts
//! away the different cryptographic libraries and provides a common interface
//! for them. The goal is to make it easy to switch between different libraries
//! and implementations without changing the code that uses them.

pub(crate) mod backend;
pub mod ec;
pub mod hmac;
pub mod okp;
pub mod rsa;

use alloc::vec::Vec;
use core::{error, fmt};

use backend::interface;

use self::backend::Backend;

/// The result type used for cryptographic operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The erased error type that is used to generalize all errors that all the
/// cryptographic libraries can return.
pub struct Error {
    inner: <Backend as interface::Backend>::Error,
}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, _f)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, _f)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        todo!()
        // error::Error::source(&self.inner)
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        todo!()
        // error::Error::cause(&self.inner)
    }
}

impl<E> From<E> for Error
where
    <Backend as interface::Backend>::Error: From<E>,
{
    fn from(err: E) -> Self {
        Self {
            inner: <Backend as interface::Backend>::Error::from(err),
        }
    }
}

/// Fills the given buffer with random data.
#[inline]
#[expect(unused)] // may be used in the future
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    <Backend as interface::Backend>::fill_random(buf).map_err(|e| Error { inner: e })
}

/// Performs a quick Sha256 of the given data.
#[inline]
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    <Backend as interface::Backend>::sha256(data)
}

/// Performs a quick Sha384 of the given data.
#[inline]
pub(crate) fn sha384(data: &[u8]) -> Vec<u8> {
    <Backend as interface::Backend>::sha384(data)
}

/// Performs a quick Sha512 of the given data.
#[inline]
pub(crate) fn sha512(data: &[u8]) -> Vec<u8> {
    <Backend as interface::Backend>::sha512(data)
}
