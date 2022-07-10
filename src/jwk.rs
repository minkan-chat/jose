//! [`JsonWebKey`] and connected things

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt::Debug;

use digest::OutputSizeUser;
use generic_array::GenericArray;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    jwa::JsonWebAlgorithm,
    policy::{Checkable, Checked, Policy},
};

mod asymmetric;
pub mod ec;
mod key_ops;
mod key_use;
pub mod okp;
mod private;
mod public;
pub mod rsa;
mod serde_impl;
pub mod symmetric;
#[doc(inline)]
pub use self::{
    asymmetric::AsymmetricJsonWebKey, key_ops::KeyOperation, key_use::KeyUsage, private::Private,
    public::Public, symmetric::SymmetricJsonWebKey,
};

/// <https://datatracker.ietf.org/doc/html/rfc7517>
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JsonWebKey {
    /// `kty` parameter section 4.1
    /// Note that the [`JsonWebKeyType`] enum does way more than just
    /// checking/storing the `kty` parameter
    #[serde(flatten)]
    key_type: JsonWebKeyType,
    /// `use` parameter section 4.2
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    key_use: Option<KeyUsage>,
    /// `key_ops` parameter section 4.3
    #[serde(
        deserialize_with = "serde_impl::deserialize_ensure_set",
        rename = "key_ops"
    )]
    // default needed because else serde will error if the `key_ops` parameter is not present
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_operations: Option<HashSet<KeyOperation>>,
    /// `alg` parameter section 4.4
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    algorithm: Option<JsonWebAlgorithm>,
    /// `kid` parameter section 4.4
    // FIXME: Consider an enum if this value is a valid JWK Thumbprint,
    // see <https://www.rfc-editor.org/rfc/rfc7638>
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// `x5u` parameter section 4.6
    // FIXME: consider using an dedicated URL type for this and ensure the protocol
    // uses TLS or some other form of integrity protection.
    // There are other things to consider, see the relevant section in the RFC.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    x509_url: Option<String>,
    /// `x5c` parameter section 4.7
    // just look at the rfc
    // FIXME: find a good way and crate to parse the DER-encoded X.509 certificate(s)
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    x509_certificate_chain: Option<Vec<String>>,
    /// `x5t` parameter section 4.8
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha1",
        deserialize_with = "serde_impl::deserialize_ga_sha1",
        rename = "x5t",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha1_thumbprint:
        Option<GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>>,
    /// `x5t#S256` parameter section 4.9
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha256",
        deserialize_with = "serde_impl::deserialize_ga_sha256",
        rename = "x5t#S256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha256_thumbprint:
        Option<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>>,
}

// TODO: implement other getters
impl JsonWebKey {
    /// A JWK MAY contain an algorithm
    pub fn algorithm(&self) -> Option<JsonWebAlgorithm> {
        self.algorithm
    }

    ///
    pub fn key_usage(&self) -> Option<&KeyUsage> {
        self.key_use.as_ref()
    }

    ///
    pub fn key_operations(&self) -> Option<&HashSet<KeyOperation>> {
        self.key_operations.as_ref()
    }
}

/// A [`JsonWebKey`] represents a cryptographic key. It can either be symmetric
/// or asymmetric. In the latter case, it can store public or private
/// information about the key. This enum represents the key types as defined in
/// [RFC 7518 section 6].
///
/// [RFC 7518 section 6]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6>
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonWebKeyType {
    /// A symmetric cryptographic key
    Symmetric(SymmetricJsonWebKey),
    /// An asymmetric cryptographic key
    Asymmetric(Box<AsymmetricJsonWebKey>),
}

impl Checkable for JsonWebKey {
    fn check<P: Policy>(self, policy: P) -> Result<Checked<Self, P>, (Self, P::Error)> {
        if let Some(alg) = self.algorithm() {
            if let Err(e) = policy.algorithm(alg) {
                return Err((self, e));
            }
        }

        if let (Some(key_use), Some(key_ops)) = (self.key_usage(), self.key_operations()) {
            if let Err(e) = policy.compare_keyops_and_keyuse(key_use, key_ops) {
                return Err((self, e));
            }
        }
        Ok(Checked::new(self, policy))
    }
}
