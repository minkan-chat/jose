use alloc::string::{String, ToString};
use core::fmt::Display;

use hashbrown::HashSet;
use thiserror_no_std::Error;

use super::{CryptographicOperation, Policy, PolicyError};
use crate::{
    jwa::{JsonWebEncryptionAlgorithm, JsonWebKeyAlgorithm, JsonWebSigningAlgorithm},
    jwk::{KeyOperation, KeyUsage},
};

/// Reasons a [`StandardPolicy`] can deny a JWK.
#[derive(Debug, Error)]
pub enum StandardPolicyFail {
    /// The `alg` field contains a Content Encryption Key, which shouldn't
    /// be used in a JWK, as they are only used once and are meant to be temporary.
    #[error("`alg` field contains a content encryption algorithm")]
    ContentEncryptionKey,
    /// A [`JsonWebKey`](crate::jwk::JsonWebKey) may not perform a
    /// [`CryptographicOperation`]
    #[error("this key may not perform this cryptographic operation")]
    OperationNotAllowed,
    /// The [`JsonWebSigningAlgorithm::None`] algorithm is not allowed as this
    /// indicates an unverified/unencrypted JWS/JWE.
    #[error("`none` algorithm is not allowed")]
    NoneAlgorithm,
    /// [`KeyUsage::Other`] can not be verified by the standard policy, thus
    /// it's simply declined and the user needs to use a custom policy to
    /// check it.
    #[error("`use` contained custom usage which can't be checked")]
    OtherKeyUsage,
    /// [`KeyOperation::Other`] can not be verified by the standard policy, thus
    /// it's simply declined and the user needs to use a custom policy to
    /// check it.
    #[error("`key_ops` contained custom operation which can't be checked")]
    OtherKeyOperation,
    /// If any of [`JsonWebSigningAlgorithm`] or [`JsonWebEncryptionAlgorithm`]
    /// contains the `Other` variant, this error will be raised by the
    /// [`StandardPolicy`] because it is not understood by the implementations
    /// provided by this library.
    ///
    /// If you use custom implementations (for example, via your own
    /// [`Signer`](crate::jws::Signer) type) and use custom values for your
    /// algorithm identification, you should provide our own [`Policy`] that
    /// compares the `Other` variants against values understood by your
    /// implementation.
    #[error("`alg` header contains an unknown value")]
    OtherAlgorithm,
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
#[derive(Debug, Default, Clone)]
pub struct StandardPolicy;

impl StandardPolicy {
    /// Create a [`StandardPolicy`]
    pub const fn new() -> Self {
        Self
    }
}

// TODO: StandardPolicy should check that the JsonWebKeyType and the provided
// Algorithm make sense
impl Policy for StandardPolicy {
    type Error = StandardPolicyFail;

    fn algorithm(&self, alg: &JsonWebKeyAlgorithm) -> Result<(), Self::Error> {
        match alg {
            JsonWebKeyAlgorithm::Encryption(JsonWebEncryptionAlgorithm::Other(_))
            | JsonWebKeyAlgorithm::Signing(JsonWebSigningAlgorithm::Other(_)) => {
                Err(StandardPolicyFail::OtherAlgorithm)
            }

            JsonWebKeyAlgorithm::ContentEncryption(_) => {
                Err(StandardPolicyFail::ContentEncryptionKey)
            }

            JsonWebKeyAlgorithm::Signing(JsonWebSigningAlgorithm::None) => {
                Err(StandardPolicyFail::NoneAlgorithm)
            }
            _ => Ok(()),
        }
    }

    fn compare_key_ops_and_use(
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

    fn may_perform_operation_key_ops(
        &self,
        operation: CryptographicOperation,
        key_ops: &HashSet<KeyOperation>,
    ) -> Result<(), Self::Error> {
        use CryptographicOperation::*;
        match operation {
            Encrypt if key_ops.contains(&KeyOperation::Encrypt) => Ok(()),
            Decrypt if key_ops.contains(&KeyOperation::Encrypt) => Ok(()),
            Sign if key_ops.contains(&KeyOperation::Sign) => Ok(()),
            Verify if key_ops.contains(&KeyOperation::Verify) => Ok(()),
            _ => Err(StandardPolicyFail::OperationNotAllowed),
        }
    }

    fn may_perform_operation_key_use(
        &self,
        operation: CryptographicOperation,
        key_use: &KeyUsage,
    ) -> Result<(), Self::Error> {
        use CryptographicOperation::*;
        match operation {
            Decrypt | Encrypt if key_use == &KeyUsage::Encryption => Ok(()),
            Sign | Verify if key_use == &KeyUsage::Signing => Ok(()),
            _ => Err(StandardPolicyFail::OperationNotAllowed),
        }
    }
}
