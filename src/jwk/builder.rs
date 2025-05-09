use alloc::{string::String, vec::Vec};
use core::convert::Infallible;

use hashbrown::HashSet;

use super::{serde_impl::Base64DerCertificate, JsonWebKey, JsonWebKeyType, KeyOperation, KeyUsage};
use crate::{
    jwa::JsonWebAlgorithm,
    jwk::policy::{Checkable, Checked, Policy},
    Uri,
};

/// Reasons the construction of a `JsonWebKey` via the
/// [`JsonWebKeyBuilder::build`] method can fail.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonWebKeyBuildError<P> {
    /// The [`JsonWebKeyType`] and [`JsonWebAlgorithm`] are not compatible.
    ///
    /// An example is usage of an RSA key with an Hmac Json web algorithm.
    #[error("the `key_type` and `algorithm` are not compatible")]
    IncompatibleKeyType,
    /// This error can only happen when using the
    /// [`build_and_check`](JsonWebKeyBuilder::build_and_check) is used and the
    /// policy check failed.
    #[error(transparent)]
    PolicyCheckFailed(P),
}

/// The builder for modifying a [`JsonWebKey`].
#[derive(Debug, Clone)]
pub struct JsonWebKeyBuilder<A> {
    pub(super) key_type: JsonWebKeyType,
    pub(super) key_use: Option<KeyUsage>,
    pub(super) key_operations: Option<HashSet<KeyOperation>>,
    pub(super) algorithm: Option<JsonWebAlgorithm>,
    pub(super) kid: Option<String>,
    pub(super) x509_url: Option<Uri>,
    pub(super) x509_certificate_chain: Vec<Base64DerCertificate>,
    pub(super) x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    pub(super) x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    pub(super) additional: A,
}

macro_rules! gen_builder_methods {
    ($($field:ident: $T:ty,)*) => {
        $(#[doc = concat!("Override the `", stringify!($field), "` for this JWK.")]
        #[inline]
        pub fn $field(mut self, $field: Option<impl Into<$T>>) -> Self {
            self.$field = $field.map(Into::into);
            self
        })*
    };
}

impl JsonWebKeyBuilder<()> {
    /// Create a new [`JsonWebKeyBuilder`] with the given key.
    pub fn new(key_type: impl Into<JsonWebKeyType>) -> Self {
        Self {
            key_type: key_type.into(),
            key_use: None,
            key_operations: None,
            algorithm: None,
            kid: None,
            x509_url: None,
            x509_certificate_chain: alloc::vec![],
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            additional: (),
        }
    }
}

impl<A> JsonWebKeyBuilder<A> {
    /// Try to construct the final [`JsonWebKey`].
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if any parameter is considered invalid. For example,
    /// if a [`JsonWebKeyType`] is not compatible with the [`JsonWebAlgorithm`]
    /// set.
    pub fn build(self) -> Result<JsonWebKey<A>, JsonWebKeyBuildError<Infallible>> {
        let Self {
            key_type,
            key_use,
            key_operations,
            algorithm,
            kid,
            x509_url,
            x509_certificate_chain,
            x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint,
            additional,
        } = self;

        if let Some(ref algorithm) = algorithm {
            if !key_type.compatible_with(algorithm) {
                return Err(JsonWebKeyBuildError::IncompatibleKeyType);
            }
        }

        Ok(JsonWebKey {
            key_type,
            key_use,
            key_operations,
            algorithm,
            kid,
            x509_url,
            x509_certificate_chain,
            x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint,
            additional,
        })
    }

    /// Try to construct the final [`JsonWebKey`], and then validates the
    /// resulting JWK using the given [`Policy`].
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if any parameter is considered invalid, or the policy
    /// check failed. For example, if a [`JsonWebKeyType`] is not compatible
    /// with the [`JsonWebAlgorithm`] set.
    // We think that this degree of complexity is acceptable and a type alias would make things even
    // more complex
    #[allow(clippy::type_complexity, clippy::result_large_err)]
    pub fn build_and_check<P: Policy>(
        self,
        policy: P,
    ) -> Result<Checked<JsonWebKey<A>, P>, JsonWebKeyBuildError<P::Error>>
    where
        A: Checkable,
    {
        self.build()
            .map_err(|e| match e {
                JsonWebKeyBuildError::IncompatibleKeyType => {
                    JsonWebKeyBuildError::IncompatibleKeyType
                }
                JsonWebKeyBuildError::PolicyCheckFailed(x) => match x {},
            })?
            .check(policy)
            .map_err(|(_, e)| JsonWebKeyBuildError::PolicyCheckFailed(e))
    }
}

impl<A> JsonWebKeyBuilder<A> {
    gen_builder_methods! {
        key_use: KeyUsage,
        key_operations: HashSet<KeyOperation>,
        algorithm: JsonWebAlgorithm,
        kid: String,
        x509_url: Uri,
        x509_certificate_sha1_thumbprint: [u8; 20],
        x509_certificate_sha256_thumbprint: [u8; 32],
    }

    /// Override the `key_type` for this JWK.
    #[inline]
    pub fn key_type(mut self, key_type: JsonWebKeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Override the `x509_certificate_chain` for this JWK.
    #[inline]
    pub fn x509_certificate_chain(mut self, x509_certificate_chain: Vec<Vec<u8>>) -> Self {
        self.x509_certificate_chain = x509_certificate_chain
            .into_iter()
            .map(Base64DerCertificate)
            .collect();
        self
    }

    /// Override the additional parameters for this JWK.
    #[inline]
    pub fn additional<N>(self, additional: N) -> JsonWebKeyBuilder<N> {
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
            additional,
        }
    }
}
