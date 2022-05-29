use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use thiserror_no_std::Error;

use crate::format::FromFormat;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Error type returned for the `verify` operation.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Indicating that the signature does not correspond to the message.
    #[error("invalid signature")]
    InvalidSignature,
    /// Failed to verify message because of unexpected reason.
    ///
    /// This may occurr when communication to a HSM fails.
    #[error(transparent)]
    Other(signature::Error),
}

/// This trait represents anything that can be used to verify a JWS, JWE, or
/// whatever.
pub trait Verifier {
    /// The `verify` operation.
    ///
    /// If the message is valid, returns `Ok(())`, if the signature is invalid,
    /// returns [`VerifyError::InvalidSignature`].
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), VerifyError>;
}

#[derive(Debug)]
pub struct Unverified<T> {
    pub(crate) value: T,
    pub(crate) signature: Vec<u8>,
    pub(crate) msg: Vec<u8>,
}

impl<T> Unverified<T> {
    pub fn decode<F>(input: F) -> Result<Self, <T as FromFormat<F>>::Error>
    where
        T: FromFormat<F>,
    {
        T::from_format(input)
    }

    pub fn verify(self, verifier: &dyn Verifier) -> Result<Verified<T>, VerifyError> {
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
