use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::format::FromFormat;

/// This trait represents anything that can be used to verify a JWS, JWE, or
/// whatever.
pub trait Verifier {
    /// The `verify` operation.
    ///
    /// If the message is valid, returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`signature::Error`] if anything went wrong during signature
    /// verification or if the signature is just invalid.
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error>;
}

/// This wrapper type represents any type that was parsed from user input,
/// but the data integrity was not verified, thus it might contain corrupted or
/// malicious data.
///
/// An [`Unverified`] struct can be verified using the [`verify`](Self::verify)
/// method.
#[derive(Debug)]
pub struct Unverified<T> {
    pub(crate) value: T,
    pub(crate) signature: Vec<u8>,
    pub(crate) msg: Vec<u8>,
}

impl<T> Unverified<T> {
    /// Parse the input format to an unverified representation of `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// the `T` type.
    pub fn decode<F>(input: F) -> Result<Self, <T as FromFormat<F>>::Error>
    where
        T: FromFormat<F>,
    {
        T::from_format(input)
    }

    /// Verify this struct using the given verifier, returning a [`Verified`]
    /// representation of the inner type.
    ///
    /// # Errors
    ///
    /// Returns [`signature::Error`] if anything went wrong during signature
    /// verification or if the signature is just invalid.
    pub fn verify(self, verifier: &mut dyn Verifier) -> Result<Verified<T>, signature::Error> {
        verifier.verify(&self.msg, &self.signature)?;
        Ok(Verified(self.value))
    }
}

/// Wrapper type around a JWS, or JWE that was verified using a [`Verifier`].
#[derive(Debug)]
pub struct Verified<T>(pub(crate) T);

impl<T> Verified<T> {
    /// Turns self into it's inner `T`.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Verified<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
