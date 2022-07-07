//! Validate jose data against some [`Policy`]
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use hashbrown::HashSet;

use crate::{
    jwa::{JsonWebSigningAlgorithm, JsonWebSigningOrEnncryptionAlgorithm},
    jwk::{KeyOperation, KeyUsage},
};

/// A type `T` that was checked against a [`Policy`] `P`
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Checked<'a, T, P>
where
    P: Policy + ?Sized,
{
    /// The [`Policy`] this `T` was checked against
    policy: &'a P,
    /// The data that were checked
    data: T,
}

impl<T, P> Deref for Checked<'_, T, P>
where
    P: Policy,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, P> DerefMut for Checked<'_, T, P>
where
    P: Policy,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<'a, T, P> Checked<'a, T, P>
where
    P: Policy,
{
    pub(crate) fn new(data: T, policy: &'a P) -> Self {
        Self { policy, data }
    }

    /// Returns the [`Policy`] that was used to validate `T`
    pub fn policy(&'_ self) -> &'_ dyn Policy {
        self.policy
    }
}

/// A trait to enforce some rules in jose
pub trait Policy {
    /// Checks the `alg` header
    ///
    /// # Errors
    ///
    /// This should return an [`Err`] if the algorithm is not accepted (e.g.
    /// because it is considered insecure)
    fn algorithm(&self, alg: JsonWebSigningOrEnncryptionAlgorithm) -> Result<(), anyhow::Error>;

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
    ) -> Result<(), anyhow::Error>;
}

/// A type that can be checked against some [`Policy`]
pub trait Checkable: Sized {
    /// Check [`self`] against a [`Policy`]
    ///
    /// # Errors
    ///
    /// Returns an error if any check against the [`Policy`] failed
    fn check<P, E>(self, policy: &P) -> Result<Checked<'_, Self, P>, (Self, anyhow::Error)>
    where
        P: Policy;
}

/// A [`Policy`] with reasonable rules. Use this struct if you want to have some
/// secure defaults.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct StandardPolicy;

impl Policy for StandardPolicy {
    fn algorithm(&self, alg: JsonWebSigningOrEnncryptionAlgorithm) -> Result<(), anyhow::Error> {
        match alg {
            JsonWebSigningOrEnncryptionAlgorithm::Signing(alg) => {
                anyhow::ensure!(
                    !matches!(alg, JsonWebSigningAlgorithm::None),
                    "`none` algorithm is not allowed"
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn compare_keyops_and_keyuse(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), anyhow::Error> {
        anyhow::ensure!(
            !matches!(key_use, KeyUsage::Other(_))
                || !key_ops.iter().any(|o| matches!(o, &KeyOperation::Other(_))),
            concat!(
                "`Other` variant not allowed in `use` and `key_ops` since they can't be checked",
            )
        );

        // TODO: check that the typed variants of KeyUsage and KeyOperation
        Ok(())
    }
}
