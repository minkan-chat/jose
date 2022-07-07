//! [`JsonWebKey`] and connected things

use alloc::{boxed::Box, string::String};
use core::fmt::Debug;

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::{
    jwa::JsonWebSigningOrEnncryptionAlgorithm,
    policy::{Checkable, Checked, Policy},
};

mod asymmetric;
pub mod ec;
pub mod okp;
mod private;
mod public;
pub mod rsa;
pub mod symmetric;
#[doc(inline)]
pub use self::{
    asymmetric::AsymmetricJsonWebKey, private::Private, public::Public,
    symmetric::SymmetricJsonWebKey,
};

/// <https://datatracker.ietf.org/doc/html/rfc7517>
#[derive(Debug, PartialEq, Eq)]
pub struct JsonWebKey {
    /// `kty` parameter section 4.1
    key_type: JsonWebKeyType,
    /// `use` parameter section 4.2
    key_use: Option<KeyUsage>,
    /// `key_ops` parameter section 4.3
    key_operations: Option<HashSet<KeyOperation>>,
    /// `alg` parameter section 4.4
    // the spec says this member is OPTIONAL but I think it should not appear
    // as Option<_> in our public api since we have to decide what algorithm
    // to use at some point (en/decryption, signing/verification) anyway.
    // FIXME: consider removing this since it could be handled by `kty`
    algorithm: Option<JsonWebSigningOrEnncryptionAlgorithm>,
    /// `kid` parameter section 4.4
    // FIXME: Consider an enum if this value is a valid JWK Thumbprint,
    // see <https://www.rfc-editor.org/rfc/rfc7638>
    kid: Option<String>,
    /// `x5u` parameter section 4.6
    // FIXME: consider using an dedicated URL type for this and ensure the protocol
    // uses TLS or some other form of integrity protection.
    // There are other things to consider, see the relevant section in the RFC.
    x509_url: Option<String>,
    /// `x5c` parameter section 4.7
    // just look at the rfc
    x509_certificate_chain: Option<String>,
    /// `x5t` parameter section 4.8
    // FIXME: sha1 is vulnerable against collision attacks and should not be used
    // If we accept this parameter, consider using the `sha1collisiondetection` crate
    // also consider using a fixed size array instead of a String since the output of these hash
    // functions has a fixed width
    x509_certificate_sha1_thumbprint: Option<String>,
    /// `x5t#S256` parameter section 4.9
    x509_certificate_sha256_thumbprint: Option<String>,
}

// TODO: implement other getters
impl JsonWebKey {
    /// A JWK MAY contain an algorithm
    pub fn algorithm(&self) -> Option<JsonWebSigningOrEnncryptionAlgorithm> {
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

/// This enum represents possible key usage (`use`) parameter as
/// defined in [Section 4.2 of RFC 7517]. All possible values are registered in
/// the [IANA `JSON Web Key Use` registry].
///
/// [Section 4.2 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
/// [IANA `JSON Web Key Use` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-use>
#[non_exhaustive]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum KeyUsage {
    /// The `sig` (signature) value
    Signing,
    /// The `enc` (encryption) value
    Encryption,
    /// Some other case-sensitive [String] that did not match any of the
    /// publicly known variants
    Other(String),
}

/// This enum represents the key operations (`key_ops`) parameter as defined in
/// [Section 4.3 of RFC 7517]. All possible values are registered in the [IANA
/// `JSON Web Key Operations` registry].
///
/// This enum SHOULD NOT be used together with the [`KeyUsage`] enum. If they
/// are both present, their information MUST be consistent.
///
/// [Section 4.3 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
/// [IANA `JSON Web Key Operations` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations>
#[non_exhaustive]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum KeyOperation {
    /// This key may compute digital signatures or MACs
    Sign,
    /// This key may verify digital signatures or MACs
    Verify,
    /// This key may encrypt content
    Encrypt,
    /// This key may decrypt content and validate decryption, if applicable
    Decrypt,
    /// This key may encrypt a key
    WrapKey,
    /// This key may decrypt a key and validate the decryption, if applicable
    UnwrapKey,
    /// This key may derive a key
    DeriveKey,
    /// This key may derive bits not to be used as a key
    DeriveBits,
    /// Some other case-sensitive [String] that did not match any of the
    /// publicly known key operations
    Other(String),
}

/// A [`JsonWebKey`](crate::jwk::JsonWebKey) represents a cryptographic key. It
/// can either be symmetric or asymmetric. In the latter case, it can store
/// public or private information about the key. This enum represents the key
/// types as defined in [RFC 7518 section 6].
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
