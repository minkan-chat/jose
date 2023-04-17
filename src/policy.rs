//! Validate jose data against some [`Policy`]

mod standard;
use core::{
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
};

use hashbrown::HashSet;
pub use standard::{StandardPolicy, StandardPolicyFail};

use crate::{
    jwa::JsonWebKeyAlgorithm,
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

impl<T, P> Checked<T, P> {
    /// Create a new [`Checked<T, P>`]
    ///
    /// **Warning**: This function can't perform any validation/checks and
    /// therefore MUST only be used after sufficient validation is already done.
    pub fn new(data: T, policy: P) -> Self
    where
        P: Policy,
    {
        Self { policy, data }
    }

    /// Turns this `Checked` into it's underlying values. `T` is the type that
    /// was checked and `P` the [`Policy`] used to check `T`
    pub fn into_inner(self) -> (T, P) {
        (self.data, self.policy)
    }

    /// Turns this `Checked` into it's underlying checked type `T`
    pub fn into_type(self) -> T {
        self.into_inner().0
    }

    /// Turns this `Checked` into it's underlying [`Policy`] `P` that was used
    /// to check `T`
    pub fn into_policy(self) -> P {
        self.into_inner().1
    }

    /// Returns the [`Policy`] that was used to validate `T`
    pub fn policy(&self) -> &P
    where
        P: Policy,
    {
        &self.policy
    }
}

/// A trait to enforce some rules in jose
pub trait Policy {
    /// The error type returned when any check of this policy fails.
    type Error: PolicyError;

    /// Checks the `alg` header
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the algorithm is not accepted (e.g.
    /// because it is considered insecure)
    fn algorithm(&self, alg: &JsonWebKeyAlgorithm) -> Result<(), Self::Error>;

    /// Compares the `use` and `key_ops` parameters
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if key_use and key_ops are inconsistent
    /// with each other
    fn compare_key_ops_and_use(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error>;

    /// Checks if a [`JsonWebKey`](crate::jwk::JsonWebKey) with the given
    /// [`KeyOperation`]s is allowed to perform a certain
    /// [`CryptographicOperation`]
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the given
    /// [`JsonWebKey`](crate::jwk::JsonWebKey) with this specific set of
    /// [`KeyOperation`]s is not allowed to perform the
    /// [`CryptographicOperation`] For example, this might be the case if
    /// key_ops only contain [`KeyOperation::Encrypt`] but the
    /// [`CryptographicOperation`] is [`Sign`](CryptographicOperation::Sign).
    fn may_perform_operation_key_ops(
        &self,
        operation: CryptographicOperation,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error>;

    /// Checks if a [`JsonWebKey`](crate::jwk::JsonWebKey) with the given
    /// [`KeyUsage`] parameter is allowed to perform a certain
    /// [`CryptographicOperation`]
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the given
    /// [`JsonWebKey`](crate::jwk::JsonWebKey) with this specific [`KeyUsage`]
    /// is not allowed to perform the [`CryptographicOperation`]
    fn may_perform_operation_key_use(
        &self,
        operation: CryptographicOperation,
        key_use: &KeyUsage,
    ) -> Result<(), Self::Error>;

    /// Checks both [`KeyUsage`] and [`KeyOperation`] for the given
    /// [`CryptographicOperation`]
    ///
    /// The default implementation just calls
    /// [`may_perform_operation_key_ops`](Self::may_perform_operation_key_ops)
    /// and [`may_perform_operation_key_use`](Self::may_perform_operation_key_use).
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the [`KeyUsage`] and [`KeyOperation`]
    /// do not allow for the [`CryptographicOperation`]
    fn may_perform_operation(
        &self,
        operation: CryptographicOperation,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        self.may_perform_operation_key_ops(operation, key_ops)?;
        self.may_perform_operation_key_use(operation, key_use)
    }
}

/// An enum used to specify a cryptographic operation
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CryptographicOperation {
    /// Create a signature (used in JWS)
    Sign,
    /// Verify a signature (used in JWS)
    Verify,
    /// Encrypt something (used in JWE)
    Encrypt,
    /// Decrypt some ciphertext (used in JWE)
    Decrypt,
    // TODO: possibly add derive key and derive bits in case they are ever needed (maybe in JWE?)
}

impl<P: Policy> Policy for &P {
    type Error = P::Error;

    fn algorithm(&self, alg: &JsonWebKeyAlgorithm) -> Result<(), Self::Error> {
        P::algorithm(self, alg)
    }

    fn compare_key_ops_and_use(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        P::compare_key_ops_and_use(self, key_use, key_ops)
    }

    fn may_perform_operation_key_ops(
        &self,
        operation: CryptographicOperation,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        P::may_perform_operation_key_ops(self, operation, key_ops)
    }

    fn may_perform_operation_key_use(
        &self,
        operation: CryptographicOperation,
        key_use: &KeyUsage,
    ) -> Result<(), Self::Error> {
        P::may_perform_operation_key_use(self, operation, key_use)
    }
}

/// An error returned by the [`Policy`] trait
pub trait PolicyError {
    /// A custom error message
    fn custom<T>(msg: T) -> Self
    where
        T: Display;
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

/// This implementation allows the default JsonWebKey (and others types with
/// additional members) to implement Checkable where there are no additional
/// members (`T = ()`)
impl Checkable for () {
    fn check<P: Policy>(self, policy: P) -> Result<Checked<Self, P>, (Self, P::Error)> {
        Ok(Checked::new(self, policy))
    }
}
