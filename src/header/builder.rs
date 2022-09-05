use alloc::{string::String, vec::Vec};

use mediatype::MediaTypeBuf;

use super::{HeaderMarker, Jwe, Jws, Protected, Unprotected};
use crate::{
    jwa::{JsonWebAlgorithm, JsonWebContentEncryptionAlgorithm},
    jwk::serde_impl::Base64DerCertificate,
    JoseHeader, JsonWebKey,
};

/// A builder to create a [`JoseHeader`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoseHeaderBuilder<T = (), A = ()> {
    /// `alg` parameter defined in section 4.1.1 in both JWE and JWS
    algorithm: Option<JsonWebAlgorithm>,
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
    additional: A,
    header_typ: Option<T>,
}

impl<T, A> JoseHeaderBuilder<T, A> {
    /// Create a new [`JoseHeader`] builder from scratch.
    pub fn new() -> JoseHeaderBuilder<T, ()> {
        JoseHeaderBuilder {
            algorithm: None,
            jwk_set_url: None,
            json_web_key: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: Vec::new(),
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            typ: None,
            content_type: None,
            additional: (),
            header_typ: None,
        }
    }

    /// Set the [algorithm](JsonWebAlgorithm) used in this JWE or JWS.
    pub fn algorithm(self, algorithm: impl Into<JsonWebAlgorithm>) -> Self {
        Self {
            algorithm: Some(algorithm.into()),
            ..self
        }
    }

    // TODO: other setters

    /// Turn this [`JoseHeader`] into an [`Protected`] header.
    ///
    /// The old header type (`T`) is discarded.
    pub fn protected(self) -> JoseHeaderBuilder<Protected, A> {
        JoseHeaderBuilder {
            algorithm: self.algorithm,
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_id,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            additional: self.additional,
            header_typ: Some(Protected {
                critical_headers: Vec::new(),
            }),
        }
    }

    /// Turn this [`JoseHeader`] into an [`Unprotected`] header.
    ///
    /// The old header (`T`) type is discarded.
    pub fn unprotected(self) -> JoseHeaderBuilder<Unprotected, A> {
        JoseHeaderBuilder {
            algorithm: self.algorithm,
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_id,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            additional: self.additional,
            header_typ: Some(Unprotected {}),
        }
    }
}

impl<T, A> JoseHeaderBuilder<T, A>
where
    T: HeaderMarker,
{
    /// Use this [`JoseHeaderBuilder`] to build a [`JoseHeader`].
    ///
    /// # Errors
    ///
    /// Returns an [`JoseHeaderBuilderError`] if required parameters are missing
    /// or invald. For example, if the `algorithm` parameter isn't set, it will
    /// return [`JoseHeaderBuilderError::MissingAlgorithm`].
    pub fn build(self) -> Result<JoseHeader<T, A>, JoseHeaderBuilderError> {
        let algorithm = self
            .algorithm
            .ok_or(JoseHeaderBuilderError::MissingAlgorithm)?;
        Ok(JoseHeader {
            algorithm,
            jwk_set_url: self.jwk_set_url,
            json_web_key: self.json_web_key,
            key_id: self.key_id,
            x509_url: self.x509_url,
            x509_certificate_chain: self.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: self.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: self.x509_certificate_sha256_thumbprint,
            typ: self.typ,
            content_type: self.content_type,
            additional: self.additional,
            header_type: self
                .header_typ
                .ok_or(JoseHeaderBuilderError::MissingHeaderType)?,
        })
    }
}

impl<T, A> JoseHeaderBuilder<T, Jwe<A>> {
    ///  Set the [content encryption
    /// algorithm](JsonWebContentEncryptionAlgorithm) for a JWE.
    pub fn content_encryption_algorithm(
        self,
        enc: impl Into<JsonWebContentEncryptionAlgorithm>,
    ) -> Self {
        Self {
            additional: Jwe {
                content_encryption_algorithm: enc.into(),
                ..self.additional
            },
            ..self
        }
    }
}

impl<T, A> JoseHeaderBuilder<T, Jws<A>> {
    /// Whether or not the payload of this JWS should be base64 encoded. The
    /// default for this parameter is `true`.
    ///
    /// If you use a detached payload, you'll probably want to set this to
    /// false.
    pub fn encode_paylod_base64(self, base64: bool) -> Self {
        Self {
            additional: Jws {
                payload_base64_url_encoded: base64,
                ..self.additional
            },
            ..self
        }
    }
}

impl<T, A> From<JoseHeader<T, A>> for JoseHeaderBuilder<T, A> {
    fn from(header: JoseHeader<T, A>) -> Self {
        JoseHeaderBuilder {
            algorithm: Some(header.algorithm),
            jwk_set_url: header.jwk_set_url,
            json_web_key: header.json_web_key,
            key_id: header.key_id,
            x509_url: header.x509_url,
            x509_certificate_chain: header.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: header.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: header.x509_certificate_sha256_thumbprint,
            typ: header.typ,
            content_type: header.content_type,
            additional: header.additional,
            header_typ: Some(header.header_type),
        }
    }
}

/// Errors returned by [`JoseHeaderBuilder::build`]
#[derive(Debug, thiserror_no_std::Error)]
pub enum JoseHeaderBuilderError {
    /// The [`JoseHeaderBuilder::algorithm`] method wasn't called during the
    /// build.
    #[error("The JOSE header is missing the `algorithm` parameter which is REQUIRED.")]
    MissingAlgorithm,
    /// There was no call made to [`JoseHeaderBuilder::protected`] or
    /// [`JoseHeaderBuikder::unprotected`].
    #[error("The JOSE header type is missing. It must be `Protected` or `Unprotected`.")]
    MissingHeaderType,
}
