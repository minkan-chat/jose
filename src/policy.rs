//! Validate jose data against some [`Policy`]

mod standard;
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use hashbrown::HashSet;
pub use standard::{StandardPolicy, StandardPolicyFail};

use crate::{
    jwa::JsonWebSigningOrEnncryptionAlgorithm,
    jwk::{KeyOperation, KeyUsage},
};

/// A type `T` that was checked against a [`Policy`] `P`
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Checked<T, P> {
    /// The [`Policy`] this `T` was checked against
    policy: P,
    /// The data that were checked
    data: T,
}

impl<T, P> Deref for Checked<T, P>
where
    P: Policy,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, P> DerefMut for Checked<T, P>
where
    P: Policy,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T, P> Checked<T, P>
where
    P: Policy,
{
    pub(crate) fn new(data: T, policy: P) -> Self {
        Self { policy, data }
    }

    /// Turns this `Checked` into it's underlying value that was checked.
    pub fn into_inner(self) -> T {
        self.data
    }

    /// Returns the [`Policy`] that was used to validate `T`
    pub fn policy(&self) -> &P {
        &self.policy
    }
}

/// A trait to enforce some rules in jose
pub trait Policy {
    /// The error type returned when any check of this policy fails.
    type Error;

    /// Checks the `alg` header
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the algorithm is not accepted (e.g.
    /// because it is considered insecure)
    fn algorithm(&self, alg: JsonWebSigningOrEnncryptionAlgorithm) -> Result<(), Self::Error>;

    /// Compares the `use` and `key_ops` parameters
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if key_use and key_ops are inconsistent
    /// with each other
    fn compare_keyops_and_keyuse(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error>;
}

impl<P: Policy> Policy for &P {
    type Error = P::Error;

    fn algorithm(&self, alg: JsonWebSigningOrEnncryptionAlgorithm) -> Result<(), Self::Error> {
        P::algorithm(self, alg)
    }

    fn compare_keyops_and_keyuse(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        P::compare_keyops_and_keyuse(self, key_use, key_ops)
    }
}

/// A type that can be checked against some [`Policy`]
pub trait Checkable: Sized {
    /// Check [`self`] against a [`Policy`]
    ///
    /// # Errors
    ///
    /// Returns an error if any check against the [`Policy`] failed
    fn check<P: Policy>(self, policy: P) -> Result<Checked<Self, P>, (Self, P::Error)>;
}
