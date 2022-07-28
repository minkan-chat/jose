use alloc::{string::String, vec::Vec};

use hashbrown::HashSet;

use super::{serde_impl::Base64DerCertificate, JsonWebKey, JsonWebKeyType, KeyOperation, KeyUsage};
use crate::jwa::JsonWebAlgorithm;

/// Reasons the construction of a `JsonWebKey` via the
/// [`JsonWebKeyBuilder::build`] method can fail.
#[derive(Debug, thiserror_no_std::Error)]
pub enum JsonWebKeyBuildError {
    /// The [`JsonWebKeyType`] and [`JsonWebAlgorithm`] are not compatible.
    ///
    /// An example is usage of an RSA key with an Hmac Json web algorithm.
    #[error("the `key_type` and `algorithm` are not compatible")]
    IncompatibleKeyType,
}

/// The builder for modifying a [`JsonWebKey`].
#[derive(Debug, Clone)]
pub struct JsonWebKeyBuilder<T> {
    pub(super) key_type: JsonWebKeyType,
    pub(super) key_use: Option<KeyUsage>,
    pub(super) key_operations: Option<HashSet<KeyOperation>>,
    pub(super) algorithm: Option<JsonWebAlgorithm>,
    pub(super) kid: Option<String>,
    pub(super) x509_url: Option<String>,
    pub(super) x509_certificate_chain: Vec<Base64DerCertificate>,
    pub(super) x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    pub(super) x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    pub(super) additional: T,
}

macro_rules! gen_builder_methods {
    ($($field:ident: $T:ty,)*) => {
        $(#[doc = concat!("Override the `", stringify!($field), "` for this JWK.")]
        #[inline]
        pub fn $field(mut self, $field: impl Into<Option<$T>>) -> Self {
            self.$field = $field.into();
            self
        })*
    };
}

impl<T> JsonWebKeyBuilder<T> {
    gen_builder_methods! {
        key_use: KeyUsage,
        key_operations: HashSet<KeyOperation>,
        algorithm: JsonWebAlgorithm,
        kid: String,
        x509_url: String,
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
    pub fn additional<NT>(self, additional: NT) -> JsonWebKeyBuilder<NT> {
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

    /// Try to construct the final [`JsonWebKey`].
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if any parameter is considered invalid. For example,
    /// if a [`JsonWebKeyType`] is not compatible with the [`JsonWebAlgorithm`]
    /// set.
    pub fn build(self) -> Result<JsonWebKey<T>, JsonWebKeyBuildError> {
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

        // FIXME: check if `algorithm` and `use` match

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
}
