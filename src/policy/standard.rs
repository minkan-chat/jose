use alloc::string::{String, ToString};
use core::fmt::Display;

use hashbrown::HashSet;
use thiserror_no_std::Error;

use super::{Policy, PolicyError};
use crate::{
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::{KeyOperation, KeyUsage},
};

/// Reasons a [`StandardPolicy`] can deny a JWK.
#[derive(Debug, Error)]
pub enum StandardPolicyFail {
    /// The [`JsonWebSigningAlgorithm::None`] algorithm is not allowed as this
    /// indicates an unverified/unencrypted JWS/JWE.
    #[error("`none` algorithm is not allowed")]
    NoneAlgorithm,
    /// [`KeyUsage::Other`] can not be verified by the standard policy, thus
    /// it's simply declined and the user needs to use a custom policy to
    /// check it.
    #[error("\"use\" contained custom usage which can't be checked")]
    OtherKeyUsage,
    /// [`KeyOperation::Other`] can not be verified by the standard policy, thus
    /// it's simply declined and the user needs to use a custom policy to
    /// check it.
    #[error("\"key_ops\" contained custom operation which can't be checked")]
    OtherKeyOperation,
    /// Used for the [`PolicyError`] implementation
    #[error("{0}")]
    Custom(String),
}

impl PolicyError for StandardPolicyFail {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Self::Custom(msg.to_string())
    }
}

/// A [`Policy`] with reasonable rules. Use this struct if you want to have some
/// secure defaults.
///
/// # Included checks
///
/// - [`JsonWebSigningAlgorithm::None`] is not allowed
/// - `use` field must not contain [`KeyUsage::Other`] because it can't be
///   verified
/// - `key_ops` field must not contain [`KeyOperation::Other`] because it can't
///   be verified
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct StandardPolicy;

// TODO: StandardPolicy should check that the JsonWebKeyType and the provided
// Algorithm make sense
impl Policy for StandardPolicy {
    type Error = StandardPolicyFail;

    fn algorithm(&self, alg: JsonWebAlgorithm) -> Result<(), Self::Error> {
        if let JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::None) = alg {
            return Err(StandardPolicyFail::NoneAlgorithm);
        }
        // TODO: match the Other variant against possible prohibited algorithms which
        // are not typed out in the api. See the IANA registry for a list

        Ok(())
    }

    fn compare_keyops_and_keyuse(
        &self,
        key_use: &KeyUsage,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        if matches!(key_use, KeyUsage::Other(..)) {
            return Err(StandardPolicyFail::OtherKeyUsage);
        }

        if key_ops.iter().any(|o| matches!(o, KeyOperation::Other(..))) {
            return Err(StandardPolicyFail::OtherKeyOperation);
        }

        // TODO: check that the typed variants of KeyUsage and KeyOperation
        Ok(())
    }
}
