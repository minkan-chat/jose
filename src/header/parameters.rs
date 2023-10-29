use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use mediatype::MediaTypeBuf;
use serde_json::Value;

use super::HeaderValue;
use crate::{jwk::serde_impl::Base64DerCertificate, JsonWebKey, UntypedAdditionalProperties};

#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct Parameters<T> {
    /// `crit` header MUST always be protected
    pub(crate) critical_headers: Option<BTreeSet<String>>,
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    pub(crate) jwk_set_url: Option<HeaderValue<String>>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    pub(crate) json_web_key: Option<HeaderValue<JsonWebKey<UntypedAdditionalProperties>>>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    pub(crate) key_id: Option<HeaderValue<String>>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    pub(crate) x509_url: Option<HeaderValue<String>>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    pub(crate) x509_certificate_chain: Option<HeaderValue<Vec<Base64DerCertificate>>>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    pub(crate) x509_certificate_sha1_thumbprint: Option<HeaderValue<[u8; 20]>>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    pub(crate) x509_certificate_sha256_thumbprint: Option<HeaderValue<[u8; 32]>>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    pub(crate) typ: Option<HeaderValue<MediaTypeBuf>>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    pub(crate) content_type: Option<HeaderValue<MediaTypeBuf>>,
    // additional parameters specific to JWS or JWE (e.g. `enc` in JWE)
    pub(crate) specific: T,
    // an untyped list of other values that are not understood by this implementation
    pub(crate) additional: BTreeMap<String, HeaderValue<Value>>,
}
