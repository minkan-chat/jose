use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;

use hashbrown::HashSet;
use mediatype::MediaTypeBuf;

use super::{
    serde_::HeaderReprOwned, HeaderMarker, Jwe, JweHeader, Jws, JwsHeader, Protected, TypeMarker,
    Unprotected,
};
use crate::{
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    jwk::serde_impl::Base64DerCertificate,
    JoseHeader, JsonWebKey,
};

/// A builder to create a [`JoseHeader`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoseHeaderBuilder<T = (), U = (), A = ()> {
    /// `alg` parameter defined in section 4.1.1 in both JWE and JWS
    // FIXME: use Url type instead
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    jwk_set_url: Option<String>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    json_web_key: Option<JsonWebKey>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    key_id: Option<String>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    x509_url: Option<String>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    x509_certificate_chain: Vec<Base64DerCertificate>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    typ: Option<MediaTypeBuf>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    content_type: Option<MediaTypeBuf>,
    partial_additional: PartialType<A>,
    header_typ: Option<T>,
    _marker: PhantomData<U>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PartialType<A> {
    Jws {
        alg: Option<JsonWebSigningAlgorithm>,
        b64: Option<bool>,
        additional: A,
    },
    Jwe {
        alg: Option<JsonWebEncryptionAlgorithm>,
        enc: Option<JsonWebContentEncryptionAlgorithm>,
        additional: A,
    },
}
impl Default for JoseHeaderBuilder<(), Jws> {
    fn default() -> Self {
        Self {
            jwk_set_url: None,
            json_web_key: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: Vec::new(),
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            typ: None,
            content_type: None,
            header_typ: None,
            partial_additional: PartialType::Jws {
                alg: None,
                b64: None,
                additional: (),
            },
            _marker: PhantomData,
        }
    }
}
impl Default for JoseHeaderBuilder<(), Jwe> {
    fn default() -> Self {
        Self {
            jwk_set_url: None,
            json_web_key: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: Vec::new(),
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            typ: None,
            content_type: None,
            header_typ: None,
            partial_additional: PartialType::Jwe {
                alg: None,
                enc: None,
                additional: (),
            },
            _marker: PhantomData,
        }
    }
}

impl<T, U> JoseHeaderBuilder<T, U>
where
    U: TypeMarker,
{
    /// Overwrite the [`JoseHeader::jwk_set_url`] parameter.
    pub fn jwk_set_url(self, url: Option<impl Into<String>>) -> Self {
        Self {
            jwk_set_url: url.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::json_web_key`] parameter.
    pub fn json_web_key(self, key: Option<impl Into<JsonWebKey>>) -> Self {
        Self {
            json_web_key: key.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::key_id`] parameter.
    pub fn key_id(self, key_id: Option<impl Into<String>>) -> Self {
        Self {
            key_id: key_id.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::x509_url`] parameter.
    pub fn x509_url(self, url: Option<impl Into<String>>) -> Self {
        Self {
            x509_url: url.map(Into::into),
            ..self
        }
    }

    // FIXME: use some better type or perform type checks to ensure that this is a
    // valid DER encoded certificate chain
    /// Overwrite the [`JoseHeader::x509_certificate_chain`] parameter.
    ///
    /// Note that every [`Item`](Iterator::Item`) in this [`Iterator`] must be a
    /// valid DER-encoded certificate and the first [`Item`](Iterator::Item)
    /// must be the End-Entity Certificate for the public key.
    pub fn x509_certificate_chain(self, chain: impl Iterator<Item = Vec<u8>>) -> Self {
        Self {
            x509_certificate_chain: chain.map(Base64DerCertificate).collect(),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::x509_certificate_sha1_thumbprint`]
    /// parameter.
    pub fn x509_certificate_sha1_thumbprint(self, thumbprint: Option<impl Into<[u8; 20]>>) -> Self {
        Self {
            x509_certificate_sha1_thumbprint: thumbprint.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::x509_certificate_sha256_thumbprint`]
    /// parameter.
    pub fn x509_certificate_sha256_thumbprint(
        self,
        thumbprint: Option<impl Into<[u8; 32]>>,
    ) -> Self {
        Self {
            x509_certificate_sha256_thumbprint: thumbprint.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::typ`] parameter.
    pub fn typ(self, typ: Option<impl Into<MediaTypeBuf>>) -> Self {
        Self {
            typ: typ.map(Into::into),
            ..self
        }
    }

    /// Overwrite the [`JoseHeader::content_type`] parameter.
    pub fn content_type(self, typ: Option<impl Into<MediaTypeBuf>>) -> Self {
        Self {
            content_type: typ.map(Into::into),
            ..self
        }
    }

    /// Turn this builder into a builder for a [`Protected`] [`JoseHeader`].
    /// Values in the old header type are discarded.
    pub fn protected(self) -> JoseHeaderBuilder<Protected, U> {
        JoseHeaderBuilder {
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_id,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            partial_additional: self.partial_additional,
            header_typ: Some(Protected {
                critical_headers: HashSet::new(),
            }),
            _marker: PhantomData,
        }
    }

    /// Turn this builder into a builder for an [`Unprotected`] [`JoseHeader`].
    /// Values in the old header type are discarded.
    pub fn unprotected(self) -> JoseHeaderBuilder<Unprotected, U> {
        JoseHeaderBuilder {
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_id,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            partial_additional: self.partial_additional,
            header_typ: Some(Unprotected {}),
            _marker: PhantomData,
        }
    }
}

impl<T, A> JoseHeaderBuilder<T, Jws<A>, A> {
    /// Overwrite the [`JwsHeader::algorithm`] parameter.
    pub fn algorithm(self, alg: impl Into<JsonWebSigningAlgorithm>) -> Self {
        Self {
            partial_additional: match self.partial_additional {
                PartialType::Jws {
                    alg: _,
                    b64,
                    additional,
                } => PartialType::Jws {
                    alg: Some(alg.into()),
                    b64,
                    additional,
                },
                _ => unreachable!(),
            },
            ..self
        }
    }

    /// Set a additional type parameter `N` and overwrite the (old) additional
    /// parameter `A`.
    // this function takes `N` directly instead of `impl Into<N>` because the
    // compiler is confused otherwise.
    pub fn additional<N>(self, additional: N) -> JoseHeaderBuilder<T, Jws<N>, N> {
        JoseHeaderBuilder {
            partial_additional: match self.partial_additional {
                PartialType::Jws {
                    alg,
                    b64,
                    additional: _,
                } => PartialType::Jws {
                    alg,
                    b64,
                    additional,
                },
                _ => unreachable!(),
            },
            content_type: self.content_type,
            header_typ: self.header_typ,
            json_web_key: self.json_web_key,
            jwk_set_url: self.jwk_set_url,
            key_id: self.key_id,
            typ: self.typ,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            x509_url: self.x509_url,
            _marker: PhantomData,
        }
    }
}

impl<T, A> JoseHeaderBuilder<T, Jwe<A>, A> {
    /// Overwrite the [`JweHeader::algorithm`] parameter.
    pub fn algorithm(self, alg: impl Into<JsonWebEncryptionAlgorithm>) -> Self {
        Self {
            partial_additional: match self.partial_additional {
                PartialType::Jwe {
                    alg: _,
                    enc,
                    additional,
                } => PartialType::Jwe {
                    alg: Some(alg.into()),
                    enc,
                    additional,
                },
                _ => unreachable!(),
            },
            ..self
        }
    }

    /// Overwrite the [`JweHeader::content_encryption_algorithm`] parameter.
    pub fn content_encryption_algorithm(
        self,
        enc: impl Into<JsonWebContentEncryptionAlgorithm>,
    ) -> Self {
        Self {
            partial_additional: match self.partial_additional {
                PartialType::Jwe {
                    alg,
                    enc: _,
                    additional,
                } => PartialType::Jwe {
                    alg,
                    enc: Some(enc.into()),
                    additional,
                },
                _ => unreachable!(),
            },
            ..self
        }
    }

    /// Set a additional type parameter `N` and overwrite the (old) additional
    /// parameter `A`.
    pub fn additional<N>(self, additional: impl Into<N>) -> JoseHeaderBuilder<T, Jwe<N>, N> {
        JoseHeaderBuilder {
            partial_additional: match self.partial_additional {
                PartialType::Jwe {
                    alg,
                    enc,
                    additional: _,
                } => PartialType::Jwe {
                    alg,
                    enc,
                    additional: additional.into(),
                },
                _ => unreachable!(),
            },
            content_type: self.content_type,
            header_typ: self.header_typ,
            json_web_key: self.json_web_key,
            jwk_set_url: self.jwk_set_url,
            key_id: self.key_id,
            typ: self.typ,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            x509_url: self.x509_url,
            _marker: PhantomData,
        }
    }
}

impl<U> JoseHeaderBuilder<Protected, U>
where
    U: TypeMarker,
{
    /// Overwrite the [`JwsHeader<Protected>::critical_headers`] parameter.
    ///
    /// Each [`Item`](Iterator::Item) must be the serialized parameter name
    /// (e.g. `cty` instead of
    /// [`content_type`](JoseHeaderBuilder::content_type)).
    pub fn critical_headers(self, critical_headers: impl Iterator<Item = String>) -> Self {
        Self {
            header_typ: Some(Protected {
                critical_headers: critical_headers.collect(),
            }),
            ..self
        }
    }
}
impl<U> JoseHeaderBuilder<Unprotected, U>
where
    U: TypeMarker,
{
    // Empty.
}

impl<A> JoseHeaderBuilder<Protected, Jws<A>> {
    /// Overwrite the [`JwsHeader<Protected>::payload_base64_url_encoded`]
    /// parameter.
    ///
    /// If set to `false`, the payload will not be base64url-encoded.
    pub fn payload_base64_url_encoded(self, encode_base64_url: bool) -> Self {
        Self {
            partial_additional: match self.partial_additional {
                PartialType::Jws {
                    alg,
                    b64: _,
                    additional,
                } => PartialType::Jws {
                    alg,
                    b64: Some(encode_base64_url),
                    additional,
                },
                _ => unreachable!(),
            },
            ..self
        }
    }
}
impl<A> JoseHeaderBuilder<Unprotected, Jws<A>> {
    // Empty.
}

impl<A> JoseHeaderBuilder<Protected, Jwe<A>> {
    // Empty.
}
impl<A> JoseHeaderBuilder<Unprotected, Jwe<A>> {
    // Empty.
}

impl<T, A> JoseHeaderBuilder<T, Jws<A>, A>
where
    T: HeaderMarker,
{
    /// Try to use this [`JoseHeaderBuilder`] to build a [`JwsHeader`].
    ///
    /// # Errors
    ///
    /// Returns an [`BuilderError`] in the following cases:
    ///
    /// * required parameters weren't set, namely `alg`
    /// * a provided parameter is malformed
    pub fn build(self) -> Result<JwsHeader<T, A>, BuilderError> {
        let (algorithm, payload_base64_url_encoded, additional) = match self.partial_additional {
            PartialType::Jws {
                alg,
                b64,
                additional,
            } => (alg.ok_or(BuilderError::MissingAlgorithm)?, b64, additional),
            _ => unreachable!(),
        };

        Ok(JoseHeader {
            inner: HeaderReprOwned {
                additional: Jws {
                    algorithm,
                    payload_base64_url_encoded,
                    additional,
                },
                content_type: self.content_type,
                header_type: self
                    .header_typ
                    .expect("build is only callable if protected or unprotected were called"),
                json_web_key: self.json_web_key,
                jwk_set_url: self.jwk_set_url,
                key_id: self.key_id,
                typ: self.typ,
                x509_certificate_chain: self.x509_certificate_chain,
                x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
                x509_url: self.x509_url,
            },
        })
    }
}

impl<T, A> JoseHeaderBuilder<T, Jwe<A>, A>
where
    T: HeaderMarker,
{
    /// Try to use this [`JoseHeaderBuilder`] to build a [`JweHeader`].
    ///
    /// # Errors
    ///
    /// Returns an [`BuilderError`] in the following cases:
    ///
    /// * required parameters weren't set, namely `alg` and `enc`
    /// * a provided parameter is malformed
    pub fn build(self) -> Result<JweHeader<T, A>, BuilderError> {
        let (algorithm, content_encryption_algorithm, additional) = match self.partial_additional {
            PartialType::Jwe {
                alg,
                enc,
                additional,
            } => (
                alg.ok_or(BuilderError::MissingAlgorithm)?,
                enc.ok_or(BuilderError::MissingContentEncryptionAlgorithm)?,
                additional,
            ),
            _ => unreachable!(),
        };

        Ok(JoseHeader {
            inner: HeaderReprOwned {
                additional: Jwe {
                    additional,
                    algorithm,
                    content_encryption_algorithm,
                },
                content_type: self.content_type,
                header_type: self
                    .header_typ
                    .expect("build is only callable if protected or unprotected were called"),
                json_web_key: self.json_web_key,
                jwk_set_url: self.jwk_set_url,
                key_id: self.key_id,
                typ: self.typ,
                x509_certificate_chain: self.x509_certificate_chain,
                x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
                x509_url: self.x509_url,
            },
        })
    }
}

/// The error returned by [`JoseHeaderBuilder::build`].
#[derive(Debug, thiserror_no_std::Error)]
pub enum BuilderError {
    /// The [`JoseHeader::algorithm`] wasn't set.
    #[error("algorithm not set")]
    MissingAlgorithm,
    /// The [`JoseHeader::content_encryption_algorithm`] wasn't set.
    #[error("content_encryption_algorithm not set")]
    MissingContentEncryptionAlgorithm,
}
