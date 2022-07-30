//! [`JsonWebKey`] and connected things

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{
    fmt::Debug,
    ops::{ControlFlow, Deref},
};

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::{
    jwa::{EcDSA, JsonWebAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    jwk::ec::{EcPrivate, EcPublic},
    policy::{Checkable, Checked, CryptographicOperation, Policy},
    sealed::Sealed,
};

pub mod ec;
pub mod okp;
pub mod rsa;
pub mod symmetric;

mod asymmetric;
mod builder;
mod key_ops;
mod key_use;
mod private;
mod public;
mod serde_impl;
mod signer;
mod verifier;

use self::serde_impl::Base64DerCertificate;
#[doc(inline)]
pub use self::{
    asymmetric::AsymmetricJsonWebKey,
    builder::{JsonWebKeyBuildError, JsonWebKeyBuilder},
    key_ops::KeyOperation,
    key_use::KeyUsage,
    private::Private,
    public::Public,
    signer::{FromJwkError, JwkSigner},
    symmetric::SymmetricJsonWebKey,
    verifier::JwkVerifier,
};

/// A [`JsonWebKey`] is a [JSON Object](serde_json::Value::Object) representing
/// the components of a cryptographic keys that can be used for
/// [JWE](crate::jwe::JsonWebEncryption) and
/// [JWS](crate::jws::JsonWebSignature).
///
/// The format of Json Web Keys is defined in [RFC 7517] with key specific
/// parameters defined in [section 6 of RFC 7518]. The [`JsonWebKey`] struct is
/// an abstract representation of all possible key types. The [`JsonWebKeyType`]
/// enum is used to specialize on concrete key type.
///
/// # Examples
///
/// Parse a JsonWebKey from its json representation:
///
/// ```
/// # // std is available in tests
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use jose::{jwk::KeyUsage, JsonWebKey};
///
/// // The following json object represents a RSA key used for signing
/// let json = r#"
/// {
///  "kty": "RSA",
///  "kid": "bilbo.baggins@hobbiton.example",
///  "use": "sig",
///  "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
///  "e": "AQAB"
/// }"#;
///
/// // deserialize the key from it's json representation using serde_json
/// let jwk: JsonWebKey = serde_json::from_str(json)?;
///
/// // You can use the JsonWebKey to access parameters defined by the spec.
/// // For example, we might want to ensure that this key is for signing by
/// // checking the `use` parameter
/// assert_eq!(jwk.key_usage(), Some(&KeyUsage::Signing));
/// # Ok(())
/// # }
/// ```
///
/// ## Additional parameters
///
/// The spec allows custom/additional parameters that are not registered in the
/// [IANA `JSON Web Key Parameters` registry]. The `T` generic parameter of
/// [`JsonWebKey<T>`] allows you to bring your own type to do just that.
///
/// To do so, create a container type that holds all your parameters (and maybe
/// even another container).
/// Imagine we have a custom parameter `intended_party` which holds a [`String`]
/// identifying the application which should use the [`JsonWebKey`]:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use jose::JsonWebKey;
/// use serde::{Deserialize, Serialize};
///
/// // don't forget to derive or implement the serde traits since they are used for (de)serialization
/// #[derive(Deserialize, Serialize)]
/// struct MyCustomParameters {
///     intended_party: String,
/// }
///
/// /// A type alias so we dont have to type so much
/// type MyJsonWebKey = JsonWebKey<MyCustomParameters>;
///
/// // consider the same key as before but this time it needs our custom parameter `intended_party`
/// let json = r#"
/// {
///  "intended_party": "my_application",
///  "kty": "RSA",
///  "kid": "bilbo.baggins@hobbiton.example",
///  "use": "sig",
///  "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
///  "e": "AQAB"
/// }"#;
///
/// let jwk: MyJsonWebKey = serde_json::from_str(json)?;
///
/// // access the custom parameter
/// assert_eq!("my_application", jwk.additional().intended_party.as_str());
/// # Ok(())
/// # }
/// ```
///
/// ### Implementing [`Checkable`] for your additional type
///
/// The [`Checkable`] trait should be implemented by types that can utilize some
/// (potentially expensive) checks to ensure their validity optionally using a
/// [`Policy`]. For example, [`JsonWebKey`] implements the [`Checkable`] trait
/// to validate some parameters which can't be validated during deserialization.
///
/// For [`JsonWebKey`] to implement [`Checkable`], your additional type also
/// needs to implement [`Checkable`]. If we recall the example from before, we
/// might want to ensure that our `intended_party` parameter containts only
/// ascii characters. An implementation for that purpose might look like this:
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use jose::policy::{Checkable, Checked, Policy, PolicyError};
/// use serde::{Deserialize, Serialize};
/// // our type from before
/// #[derive(Deserialize, Serialize)]
/// struct MyCustomParameters {
///     intended_party: String,
/// }
///
/// impl Checkable for MyCustomParameters {
///     fn check<P: Policy>(self, policy: P) -> Result<Checked<Self, P>, (Self, P::Error)> {
///         if self.intended_party.is_ascii() {
///             Ok(Checked::new(self, policy))
///         } else {
///             Err((
///                 self,
///                 <P::Error as PolicyError>::custom(
///                     "`intended_party` parameter must contain ascii characters only",
///                 ),
///             ))
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// [RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517>
/// [section 6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6>
/// [IANA `Json Web Key Parameters` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters>
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct JsonWebKey<T = ()> {
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
        rename = "key_ops",
        skip_serializing_if = "Option::is_none",
        // default needed because else serde will error if the `key_ops` parameter is not present
        default
    )]
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
    // If the `x5c` parameter is not present, this will be an empty Vec
    // FIXME: find a good way and crate to parse the DER-encoded X.509 certificate(s)
    #[serde(rename = "x5c", skip_serializing_if = "Vec::is_empty", default)]
    x509_certificate_chain: Vec<Base64DerCertificate>,
    /// `x5t` parameter section 4.8
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha1",
        deserialize_with = "serde_impl::deserialize_ga_sha1",
        rename = "x5t",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    /// `x5t#S256` parameter section 4.9
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha256",
        deserialize_with = "serde_impl::deserialize_ga_sha256",
        rename = "x5t#S256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    /// Additional members in the JWK as permitted by the fourth paragraph of
    /// [section 4]
    ///
    /// [section 4]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4>
    #[serde(flatten)]
    additional: T,
}

impl JsonWebKey<()> {
    fn new(key_type: JsonWebKeyType) -> Self {
        Self {
            key_type,
            key_use: None,
            key_operations: None,
            algorithm: None,
            kid: None,
            x509_url: None,
            x509_certificate_chain: vec![],
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            additional: (),
        }
    }
}

impl<T> JsonWebKey<T> {
    /// Create a [`JsonWebKeyBuilder`] to construct a new JWK.
    pub fn builder(key_type: impl Into<JsonWebKeyType>) -> JsonWebKeyBuilder<()> {
        JsonWebKeyBuilder::new(key_type)
    }

    /// Turn this Json Web Key into a builder to modify it's contents.
    pub fn into_builder(self) -> JsonWebKeyBuilder<T> {
        JsonWebKeyBuilder {
            key_type: self.key_type,
            key_use: self.key_use,
            key_operations: self.key_operations,
            algorithm: self.algorithm,
            kid: self.kid,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            additional: self.additional,
        }
    }

    /// [Section 4.1 of RFC 7517] defines the `kty` (Key Type) Parameter.
    ///
    /// Since the `kty` parameter is used to distinguish different key types, we
    /// use the [`JsonWebKeyType`] to also store key specific data. You can
    /// match the [`JsonWebKeyType`] to determine the exact key type used.
    ///
    /// [Section 4.1 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    pub fn key_type(&self) -> &JsonWebKeyType {
        &self.key_type
    }

    /// [Section 4.2 of RFC 7517] defines the `use` (Public Key Use) Parameter.
    ///
    /// See the documentation of [`KeyUsage`] for details.
    ///
    /// [Section 4.2 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
    pub fn key_usage(&self) -> Option<&KeyUsage> {
        self.key_use.as_ref()
    }

    /// [Section 4.3 of RFC 7517] defines the `key_ops` (Key Operations)
    /// Parameter.
    ///
    /// It is a set of different operations a key may perform.
    /// See the documentation of [`KeyOperation`] for details.
    ///
    /// [Section 4.3 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
    pub fn key_operations(&self) -> Option<&HashSet<KeyOperation>> {
        self.key_operations.as_ref()
    }

    /// [Section 4.4 of RFC 7517] defines the `alg` (Algorithm) Parameter.
    ///
    /// See the documentation of [`JsonWebAlgorithm`] for details.
    ///
    /// [Section 4.4 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.4>
    pub fn algorithm(&self) -> Option<JsonWebAlgorithm> {
        self.algorithm
    }

    /// [Section 4.5 of RFC 7517] defines the `kid` (Key ID) Parameter.
    ///
    /// [Section 4.5 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.5>
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// [Section 4.6 of RFC 7517] defines the `x5u` (X.509 URL) Parameter.
    ///
    /// [Section 4.6 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.6>
    pub fn x509_url(&self) -> Option<&str> {
        self.x509_url.as_deref()
    }

    /// [Section 4.7 of RFC 7517] defines the `x5c` (X.509 Certificate Chain)
    /// Parameter.
    ///
    /// This parameter is a list of X.509 certificates. The first certificate in
    /// the [`ExactSizeIterator`] returned by this method is the PKIX
    /// certificate containing the key value as required by the RFC. Note
    /// that this parameter is OPTIONAL and if not present, this
    /// [`ExactSizeIterator`] will be empty ([`next`](Iterator::next) will be
    /// [`None`] and [`len`](ExactSizeIterator::len) will be `0`).
    ///
    /// Each [`Item`](Iterator::Item) will be the byte representation of a
    /// DER-encoded X.509 certificate.
    ///
    /// [Section 4.7 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.7>
    pub fn x509_certificate_chain(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.x509_certificate_chain.iter().map(Deref::deref)
    }

    /// [Section 4.8 of RFC 7517] defines the `x5t` (X.509 Certificate SHA-1
    /// Thumbprint) Parameter.
    ///
    /// It is the SHA-1 hash of the DER-encoded X.509 certificate.
    ///
    /// # Warning: Cryptographically broken!
    ///
    /// TL;DR: check if you can use the [SHA-256
    /// thumbprint](JsonWebKey::x509_certificate_sha256_thumbprint) instead.
    ///
    /// The following text is taken from the [`sha1`] crate: \
    /// The SHA-1 hash function should be considered cryptographically broken
    /// and unsuitable for further use in any security critical capacity, as it
    /// is [practically vulnerable to chosen-prefix collisions](https://sha-mbles.github.io/).
    ///
    /// [Section 4.8 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.8>
    // replace the hardcoded output size with the Sha1::OutputsizeUser value then
    // they use const generics
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&[u8; 20]> {
        self.x509_certificate_sha1_thumbprint.as_ref()
    }

    /// [Section 4.9 of RFC 7517] defines the `x5t#S256` (X.509 Certificate
    /// SHA-256 Thumbprint) Parameter.
    ///
    /// It is the SHA-256 hash of the DER-encoded X.509 certificate.
    ///
    /// [Section 4.9 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.9>
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&[u8; 32]> {
        self.x509_certificate_sha256_thumbprint.as_ref()
    }

    /// Additional members in the [`JsonWebKey`] as permitted by the fourth
    /// paragraph of [section 4 in RFC 7517]
    ///
    /// [section 4 in RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-4>
    pub fn additional(&self) -> &T {
        &self.additional
    }
}

impl<T> Checkable for JsonWebKey<T>
where
    T: Checkable,
{
    fn check<P: Policy>(self, policy: P) -> Result<Checked<Self, P>, (Self, P::Error)> {
        if let Some(alg) = self.algorithm() {
            if let Err(e) = policy.algorithm(alg) {
                return Err((self, e));
            }

            let operations = match alg {
                JsonWebAlgorithm::Encryption(..) => [
                    CryptographicOperation::Encrypt,
                    CryptographicOperation::Decrypt,
                ],
                JsonWebAlgorithm::Signing(..) => {
                    [CryptographicOperation::Sign, CryptographicOperation::Verify]
                }
            };
            debug_assert!(!operations.is_empty());

            if let Some(key_use) = self.key_usage() {
                // The following ensures that at least one `operation` is allowed with the
                // current key usage (returns Ok(())). If Ok(()) is returned, it
                // short-circuits
                match operations.iter().try_fold(None, |_, operation| {
                    match policy.may_perform_operation_key_use(*operation, key_use) {
                        Ok(_) => ControlFlow::Break(()),
                        Err(err) => ControlFlow::Continue(Some(err)),
                    }
                }) {
                    ControlFlow::Break(_) => (),
                    ControlFlow::Continue(err) => {
                        return Err((
                            self,
                            // Safety
                            //
                            // First of, this could use unwrap_unchecked but doesn't since we
                            // forbid unsafe code in this crate. However, it would be safe,
                            // because: the call to the Policy returns
                            // Result<(), err> and if it's Ok, it
                            // will break and this branch will never get called. If the call
                            // failed, the inital state of `None` will be set to
                            // Continue(Some(err)), which will be the value in this branch
                            err.expect("at least one call has been made to the Policy"),
                        ));
                    }
                }
            }

            if let Some(key_ops) = self.key_operations() {
                // The following ensures tthat at loeast one `operation` is allowed with the
                // current key operations. If Ok(()) is returned, it short-circuits.
                // For example, a key might have a signing algorithm, but only
                // `KeyOperation::Verify` is set since it is a public key and can't perform
                // signing operations. In this case, it has the same signing algorithm.
                match operations.iter().try_fold(None, |_, operation| {
                    match policy.may_perform_operation_key_ops(*operation, key_ops) {
                        Ok(_) => ControlFlow::Break(()),
                        Err(err) => ControlFlow::Continue(Some(err)),
                    }
                }) {
                    ControlFlow::Break(_) => (),
                    ControlFlow::Continue(err) => {
                        return Err((
                            self,
                            // Same rules as for the code with `key_usage` from above apply.
                            err.expect("at leat one call has been made to the Policy"),
                        ));
                    }
                }
            }
        }

        if let (Some(key_use), Some(key_ops)) = (self.key_usage(), self.key_operations()) {
            if let Err(e) = policy.compare_key_ops_and_use(key_use, key_ops) {
                return Err((self, e));
            }
        }

        match self.additional.check(policy) {
            Err(e) => Err((
                Self {
                    additional: e.0,
                    ..self
                },
                e.1,
            )),
            Ok(o) => {
                let (additional, p) = o.into_inner();
                Ok(Checked::new(Self { additional, ..self }, p))
            }
        }
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

impl JsonWebKeyType {
    pub(self) fn compatible_with(&self, alg: &JsonWebAlgorithm) -> bool {
        use JsonWebAlgorithm::*;
        use JsonWebKeyType::*;

        // it is unreadable with the matches! macro and there's no benefit
        #[allow(clippy::match_like_matches_macro)]
        match (self, alg) {
            (
                Symmetric(SymmetricJsonWebKey::OctetSequence(..)),
                Signing(JsonWebSigningAlgorithm::Hmac(..))
                | Encryption(JsonWebEncryptionAlgorithm::Direct)
                | Encryption(JsonWebEncryptionAlgorithm::AesKw(..))
                | Encryption(JsonWebEncryptionAlgorithm::AesGcmKw(..))
                | Encryption(JsonWebEncryptionAlgorithm::Pbes2(..)),
            ) => true,
            (Asymmetric(key), alg) => match (&**key, alg) {
                (
                    AsymmetricJsonWebKey::Public(Public::Ec(..))
                    | AsymmetricJsonWebKey::Private(Private::Ec(..)),
                    Encryption(JsonWebEncryptionAlgorithm::EcDhES(..)),
                )
                | (
                    AsymmetricJsonWebKey::Public(Public::Ec(EcPublic::P256(..)))
                    | AsymmetricJsonWebKey::Private(Private::Ec(EcPrivate::P256(..))),
                    Signing(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256)),
                )
                | (
                    AsymmetricJsonWebKey::Public(Public::Ec(EcPublic::P384(..)))
                    | AsymmetricJsonWebKey::Private(Private::Ec(EcPrivate::P384(..))),
                    Signing(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es384)),
                )
                | (
                    AsymmetricJsonWebKey::Public(Public::Ec(EcPublic::Secp256k1(..)))
                    | AsymmetricJsonWebKey::Private(Private::Ec(EcPrivate::Secp256k1(..))),
                    Signing(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256K)),
                )
                | (
                    AsymmetricJsonWebKey::Public(Public::Rsa(..))
                    | AsymmetricJsonWebKey::Private(Private::Rsa(..)),
                    Signing(JsonWebSigningAlgorithm::Rsa(..))
                    | Encryption(JsonWebEncryptionAlgorithm::Rsa1_5)
                    | Encryption(JsonWebEncryptionAlgorithm::RsaesOaep(..)),
                ) => true,
                _ => false,
            },
            _ => false,
        }
    }
}

/// A trait for a [`Signer`](crate::jws::Signer) or
/// [`Verifier`](crate::jws::Verifier) to implement if it can be created from
/// key material as long as the algorithm is known
pub trait FromKey<K>: Sized {
    /// The error returned if the conversion failed
    type Error;

    /// Turn `K` into this [`Signer`](crate::jws::Signer) or
    /// [`Verifier`](crate::jws::Verifier).
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion failed
    fn from_key(value: K, alg: JsonWebAlgorithm) -> Result<Self, Self::Error>;
}

/// A trait for different key types to implement if they can be converted into a
/// [`JsonWebKey`].
///
/// This trait, and deserialization, is the only public way of creating a
/// [`JsonWebKey`].
pub trait IntoJsonWebKey: Sealed {
    /// One key type may be used for multiple [`JsonWebAlgorithm`]s.
    ///
    /// This algorithm can be specified using this type.
    type Algorithm;

    /// The error that can occurr when converting this key into a JWK.
    type Error;

    /// Turns this key mateiral into a [`JsonWebKey`] for the given algorithm.
    ///
    /// If the given argument is `None`, the `alg` header field of the resulting
    /// JWK will be None.
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if the conversion fails.
    fn into_jwk(self, alg: impl Into<Option<Self::Algorithm>>) -> Result<JsonWebKey, Self::Error>;
}
