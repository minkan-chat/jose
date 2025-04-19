use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::marker::PhantomData;

use mediatype::MediaTypeBuf;
use serde_json::Value;

use super::{HeaderValue, Jwe, Jws, Type};
use crate::{
    format::Format,
    header::parameters::Parameters,
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    jwk::serde_impl::Base64DerCertificate,
    JoseHeader, JsonWebKey, UntypedAdditionalProperties, Uri,
};

/// A builder for a [`JoseHeader`].
#[derive(Debug)]
#[non_exhaustive]
pub struct JoseHeaderBuilder<F, T> {
    // data
    critical_headers: Option<BTreeSet<String>>,
    jwk_set_url: Option<HeaderValue<Uri>>,
    json_web_key: Option<HeaderValue<JsonWebKey<UntypedAdditionalProperties>>>,
    key_identifier: Option<HeaderValue<String>>,
    x509_url: Option<HeaderValue<Uri>>,
    x509_certificate_chain: Option<HeaderValue<Vec<Vec<u8>>>>,
    x509_certificate_sha1_thumbprint: Option<HeaderValue<[u8; 20]>>,
    x509_certificate_sha256_thumbprint: Option<HeaderValue<[u8; 32]>>,
    typ: Option<HeaderValue<MediaTypeBuf>>,
    content_type: Option<HeaderValue<MediaTypeBuf>>,
    additional: BTreeMap<String, HeaderValue<Value>>,
    specific: Specific,
    _phantom: PhantomData<(F, T)>,
}

impl<F, T> JoseHeaderBuilder<F, T>
where
    F: Format,
    T: Type,
{
    /// Set the [`critical_headers`](crate::JoseHeader::critical_headers)
    /// parameter.
    pub fn critical_headers(self, critical_headers: Option<BTreeSet<String>>) -> Self {
        // since `crit` header is not allowed to be an empty array, an empty set is
        // discarded setting `None` will remove any existing critical headers
        // that may already be present
        Self {
            critical_headers,
            ..self
        }
    }

    /// Set [additional](crate::JoseHeader::additional) parameters.
    ///
    /// Note: Do not push parameter names that are understood by this
    /// implementation. Instead, use the appropriate method to set the parameter
    /// directly.
    pub fn additional(self, additional: BTreeMap<String, HeaderValue<Value>>) -> Self {
        Self { additional, ..self }
    }

    /// Create a new [`JoseHeaderBuilder`] in order to build a [`JoseHeader`].
    pub fn new() -> Self {
        Self {
            critical_headers: None,
            jwk_set_url: None,
            json_web_key: None,
            key_identifier: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            typ: None,
            content_type: None,
            additional: BTreeMap::new(),
            specific: T::specific_default(),
            _phantom: PhantomData,
        }
    }

    fn build_parameters(self) -> Result<(Parameters<()>, Specific), JoseHeaderBuilderError> {
        // oh dear god
        let x509_certificate_chain = self
            .x509_certificate_chain
            .map(|v| v.map(|v| v.into_iter().map(Base64DerCertificate).collect::<Vec<_>>()));

        // FIXME: check if additional parameters contain parameters that are understood
        // by our implementation and that should be set via their methods instead.

        let parameters = Parameters {
            critical_headers: self.critical_headers,
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_identifier,
            x509_url: self.x509_url,
            x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            specific: (),
            additional: self.additional,
        };
        Ok((parameters, self.specific))
    }

    /// Create a [`JoseHeaderBuilder`] from a [`JoseHeader`] preserving the
    /// parameters.
    pub fn from_header(header: JoseHeader<F, T>) -> Self {
        let parameters = header.parameters;
        let specific = parameters.specific.into_specific();

        let x509_certificate_chain = parameters
            .x509_certificate_chain
            .map(|v| v.map(|v| v.into_iter().map(|v| v.0).collect::<Vec<_>>()));
        Self {
            critical_headers: parameters.critical_headers,
            jwk_set_url: parameters.jwk_set_url,
            json_web_key: parameters.json_web_key,
            key_identifier: parameters.key_id,
            x509_url: parameters.x509_url,
            x509_certificate_chain,
            x509_certificate_sha1_thumbprint: parameters.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: parameters.x509_certificate_sha256_thumbprint,
            typ: parameters.typ,
            content_type: parameters.content_type,
            additional: parameters.additional,
            specific,
            _phantom: PhantomData,
        }
    }
}

impl<F, T> Default for JoseHeaderBuilder<F, T>
where
    F: Format,
    T: Type,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Specific parameters for Jws and Jwe. See [`Jws`] and [`Jwe`]
#[derive(Debug)]
#[non_exhaustive]
pub enum Specific {
    Jws {
        algorithm: Option<HeaderValue<JsonWebSigningAlgorithm>>,
        // default: true
        payload_base64_url_encoded: Option<bool>,
    },
    Jwe {
        algorithm: Option<HeaderValue<JsonWebEncryptionAlgorithm>>,
        content_encryption_algorithm: Option<HeaderValue<JsonWebContentEncryptionAlgorithm>>,
    },
}

/// Errors that may occur while building a [`JoseHeader`] via
/// [`JoseHeaderBuilder::build`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JoseHeaderBuilderError {
    /// There is no algorithm specified. Specify an algorithm via
    /// [`JoseHeaderBuilder::algorithm`].
    #[error("no algorithm set")]
    MissingAlgorithm,
    /// There is no content encryption algorithm specified. Specify an content
    /// encryption algorithm via
    /// [`JoseHeaderBuilder::content_encryption_algorithm`].
    ///
    /// Note: This error may only occur while building a [`JoseHeader`] for
    /// [`Jwe`].
    #[error("no content encryption algorithm set")]
    MissingContentEncryptionAlgorithm,
    /// One or more certificates in the X.509 certificate chain (set via
    /// [`JoseHeaderBuilder::x509_certificate_chain`]) are invalid. E.g. not
    /// valid DER-encoded.
    #[error("the certificates in the certificate chain are invalid")]
    InvalidX509CertificateChain,
}

impl<F> JoseHeaderBuilder<F, Jws>
where
    F: Format,
{
    /// Set the [`algorithm`](crate::JoseHeader::algorithm) parameter for
    /// [`Jws`].
    pub fn algorithm(self, algorithm: HeaderValue<JsonWebSigningAlgorithm>) -> Self {
        let specific = Specific::Jws {
            algorithm: Some(algorithm),
            payload_base64_url_encoded: match self.specific {
                Specific::Jws {
                    algorithm: _,
                    payload_base64_url_encoded,
                } => payload_base64_url_encoded,
                // implementation must ensure a JoseHeaderBuilder<F, Jws> cannot be turned into an
                // JoseHeaderBuilder<F, Jwe>
                _ => unreachable!(),
            },
        };
        Self { specific, ..self }
    }

    /// Set the [`payload_base64_url_encoded`](crate::JoseHeader::payload_base64_url_encoded) parameter for [`Jws`].
    pub fn payload_base64_url_encoded(self, payload_base64_url_encoded: bool) -> Self {
        let specific = Specific::Jws {
            algorithm: match self.specific {
                Specific::Jws {
                    algorithm,
                    payload_base64_url_encoded: _,
                } => algorithm,
                _ => unreachable!(),
            },
            payload_base64_url_encoded: Some(payload_base64_url_encoded),
        };
        Self { specific, ..self }
    }

    /// Try to build a [`JoseHeader`].
    ///
    /// # Errors
    ///
    /// Returns an error if any of the values provided by the builder are
    /// invalid. See [`JoseHeaderBuilderError`] for details.
    pub fn build(self) -> Result<JoseHeader<F, Jws>, JoseHeaderBuilderError> {
        let (parameters, specific) = self.build_parameters()?;

        let (algorithm, payload_base64_url_encoded) = match specific {
            Specific::Jws {
                algorithm,
                payload_base64_url_encoded,
            } => (
                algorithm.ok_or(JoseHeaderBuilderError::MissingAlgorithm)?,
                payload_base64_url_encoded,
            ),
            _ => unreachable!(),
        };
        let specific = Jws {
            algorithm,
            payload_base64_url_encoded,
        };
        Ok(JoseHeader {
            _format: PhantomData,
            parameters: Parameters {
                specific,
                critical_headers: parameters.critical_headers,
                jwk_set_url: parameters.jwk_set_url,
                json_web_key: parameters.json_web_key,
                key_id: parameters.key_id,
                x509_url: parameters.x509_url,
                x509_certificate_chain: parameters.x509_certificate_chain,
                x509_certificate_sha1_thumbprint: parameters.x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint: parameters.x509_certificate_sha256_thumbprint,
                typ: parameters.typ,
                content_type: parameters.content_type,
                additional: parameters.additional,
            },
        })
    }
}

impl<F> JoseHeaderBuilder<F, Jwe>
where
    F: Format,
{
    /// Set the [`algorithm`](crate::JoseHeader::algorithm) parameter for
    /// [`Jwe`].
    pub fn algorithm(self, algorithm: HeaderValue<JsonWebEncryptionAlgorithm>) -> Self {
        let specific = Specific::Jwe {
            algorithm: Some(algorithm),
            content_encryption_algorithm: match self.specific {
                Specific::Jwe {
                    algorithm: _,
                    content_encryption_algorithm,
                } => content_encryption_algorithm,
                _ => unreachable!(),
            },
        };
        Self { specific, ..self }
    }

    /// Set the [`content_encryption_algorithm`](crate::JoseHeader::content_encryption_algorithm) parameter for [`Jwe`].
    pub fn content_encryption_algorithm(
        self,
        content_encryption_algorithm: HeaderValue<JsonWebContentEncryptionAlgorithm>,
    ) -> Self {
        let specific = Specific::Jwe {
            algorithm: match self.specific {
                Specific::Jwe {
                    algorithm,
                    content_encryption_algorithm: _,
                } => algorithm,
                _ => unreachable!(),
            },
            content_encryption_algorithm: Some(content_encryption_algorithm),
        };
        Self { specific, ..self }
    }

    /// Try to build a [`JoseHeader`].
    ///
    /// # Errors
    ///
    /// Returns an error if any of the values provided by the builder are
    /// invalid. See [`JoseHeaderBuilderError`] for details.
    pub fn build(self) -> Result<JoseHeader<F, Jwe>, JoseHeaderBuilderError> {
        let (parameters, specific) = self.build_parameters()?;
        let (algorithm, content_encryption_algorithm) = match specific {
            Specific::Jwe {
                algorithm,
                content_encryption_algorithm,
            } => (
                algorithm.ok_or(JoseHeaderBuilderError::MissingAlgorithm)?,
                content_encryption_algorithm.ok_or(JoseHeaderBuilderError::MissingAlgorithm)?,
            ),
            _ => unreachable!(),
        };
        let specific = Jwe {
            algorithm,
            content_encryption_algorithm,
        };

        Ok(JoseHeader {
            _format: PhantomData,
            parameters: Parameters {
                specific,
                critical_headers: parameters.critical_headers,
                jwk_set_url: parameters.jwk_set_url,
                json_web_key: parameters.json_web_key,
                key_id: parameters.key_id,
                x509_url: parameters.x509_url,
                x509_certificate_chain: parameters.x509_certificate_chain,
                x509_certificate_sha1_thumbprint: parameters.x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint: parameters.x509_certificate_sha256_thumbprint,
                typ: parameters.typ,
                content_type: parameters.content_type,
                additional: parameters.additional,
            },
        })
    }
}

macro_rules! setter {
    ($($parameter:ident: $parameter_typ:ty),+,) => {
        impl<F, T> JoseHeaderBuilder<F, T>
        where
            F: Format,
            T: Type,
        {
            $(
            #[doc = concat!("Set the [`", stringify!($parameter), "`](crate::JoseHeader::", stringify!($parameter), ") parameter.")]
            pub fn $parameter(self, $parameter: Option<HeaderValue<$parameter_typ>>) -> Self {
                Self {
                    $parameter,
                    ..self
                }
            }
            )+
        }
    };
}

setter! {
    x509_certificate_chain: Vec<Vec<u8>>,
    jwk_set_url: Uri,
    json_web_key: JsonWebKey<UntypedAdditionalProperties>,
    key_identifier: String,
    x509_url: Uri,
    x509_certificate_sha1_thumbprint: [u8; 20],
    x509_certificate_sha256_thumbprint: [u8; 32],
    typ: MediaTypeBuf,
    content_type: MediaTypeBuf,
}
