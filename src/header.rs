//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
use alloc::{format, string::String, vec::Vec};
use core::str::FromStr;

use mediatype::MediaTypeBuf;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    jwa::{JsonWebAlgorithm, JsonWebContentEncryptionAlgorithm},
    jwk::serde_impl::{self, Base64DerCertificate},
    sealed::Sealed,
    JsonWebKey,
};

mod builder;

#[doc(inline)]
pub use builder::{JoseHeaderBuilder, JoseHeaderBuilderError};

// TODO: documentation for jose header
// TODO: builder type for jose header
/// [section 4]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
/// [public]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
/// [private]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
// FIXME: can't derive `Hash` because `JsonWebKey` does not implement it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct JoseHeader<T = (), A = ()> {
    // Shared parameters between JWS and JWE
    /// `alg` parameter defined in section 4.1.1 in both JWE and JWS
    algorithm: JsonWebAlgorithm,
    // FIXME: use Url type instead
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jku")]
    jwk_set_url: Option<String>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jwk")]
    json_web_key: Option<JsonWebKey>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "kid")]
    key_id: Option<String>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5u")]
    x509_url: Option<String>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    #[serde(skip_serializing_if = "Vec::is_empty", default, rename = "x5u")]
    x509_certificate_chain: Vec<Base64DerCertificate>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha1",
        deserialize_with = "serde_impl::deserialize_ga_sha1",
        rename = "x5t",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha256",
        deserialize_with = "serde_impl::deserialize_ga_sha256",
        rename = "x5t#S256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype"
    )]
    typ: Option<MediaTypeBuf>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        rename = "cty"
    )]
    content_type: Option<MediaTypeBuf>,
    /// Additional parameters defined by the generic parameter `A`
    #[serde(flatten)]
    additional: A,
    /// Additional parameters which are only present in a specific type of
    /// header ([`Protected`] and [`Unprotected`])
    #[serde(flatten)]
    header_type: T,
}

/// A marker trait which specifies where a [`JoseHeader`] can appear.
///
/// For details, see [`Protected`] and [`Unprotected`]
pub trait HeaderMarker: Sealed {}

/// Marker struct for a [`JoseHeader`] that is integrity protected (part of the
/// signature).
#[derive(Debug, Hash, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Protected {
    /// `crit` parameter as defined in section 4.1.11 of JWS and section 4.1.13
    /// of JWE
    #[serde(rename = "crit", default, skip_serializing_if = "Vec::is_empty")]
    critical_headers: Vec<String>,
}

/// Marker struct for a [`JoseHeader`] that is not integrity protected (not part
/// of the signature). Any parameters in this header cannot be trusted.
#[derive(Debug, Hash, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Unprotected {}

impl Sealed for Protected {}
impl Sealed for Unprotected {}
impl HeaderMarker for Protected {}
impl HeaderMarker for Unprotected {}

/// Header parameters that are specific to encryption
#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct Jwe<A> {
    // TODO: JWE Headers
    #[serde(rename = "enc")]
    content_encryption_algorithm: JsonWebContentEncryptionAlgorithm,
    #[serde(flatten)]
    additional: A,
}

impl<A> AsRef<A> for Jwe<A> {
    fn as_ref(&self) -> &A {
        &self.additional
    }
}

/// Header parameters that are specific to signatures
#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct Jws<A> {
    /// `b64` parameter as defined by RFC 7797. This parameter is optional and
    /// it's default value is `true`.
    ///
    /// If this value is `false`, the payload of the JWS is not base64 urlsafe
    /// encoded. This can work for simple stuff like a hex string, but will
    /// often cause parsing errors. Use of this option makes sense if the
    /// payload of a JWS is detached.
    ///
    /// Note: In a JsonWebToken, this value MUST always be true, e.g. the
    /// payload MUST NOT use the unencoded payload option.
    #[serde(rename = "b64", default = "returns_true")]
    payload_base64_url_encoded: bool,
    #[serde(flatten)]
    additional: A,
}

impl<A> AsRef<A> for Jws<A> {
    fn as_ref(&self) -> &A {
        &self.additional
    }
}

/// A [`JoseHeader`] used with Json Web Signatures
pub type JwsHeader<T, A> = JoseHeader<T, Jws<A>>;
/// A [`JoseHeader`] used with Json Web Encryption
pub type JweHeader<T, A> = JoseHeader<T, Jwe<A>>;

// general implementation for protected and unprotected headers in both jwe and
// jws
impl<T, A> JoseHeader<T, A>
where
    T: HeaderMarker,
{
    /// Convert this [`JoseHeader`] back to a [`JoseHeaderBuilder`]
    pub fn to_builder(self) -> JoseHeaderBuilder<T, A> {
        JoseHeaderBuilder::from(self)
    }

    /// The [algorithm](JsonWebAlgorithm) used in this JWS or JWE
    pub fn algorithm(&self) -> JsonWebAlgorithm {
        self.algorithm
    }
    // TODO: add other getters
}

impl<A> JoseHeader<Protected, A> {
    // implementation for protected headers in both jwe and jws
}

impl<A> JoseHeader<Unprotected, A> {
    // implementation for unprotected headers in both jwe and jws
}

impl<T, A> JwsHeader<T, A>
where
    T: HeaderMarker,
{
    // implementation for protected and unprotected headers in jws
}

impl<A> JwsHeader<Protected, A> {
    // implementation for protected headers in jws
}

impl<A> JwsHeader<Unprotected, A> {
    // implementation for unprotected headers in jws
}

impl<T, A> JweHeader<T, A>
where
    T: HeaderMarker,
{
    // implementation for protected and unprotected headers in jwe
}

impl<A> JweHeader<Protected, A> {
    // implementation for protected headers in jwe
}

impl<A> JweHeader<Unprotected, A> {
    // implementation for unprotected headers in jwe
}

impl<T, A> AsRef<A> for JoseHeader<T, A> {
    fn as_ref(&self) -> &A {
        &self.additional
    }
}

/// Just a function that always returns true. It is used in the `#[serde(default
/// = "fn")]` attribute
fn returns_true() -> bool {
    true
}

fn deserialize_mediatype<'de, D>(deserializer: D) -> Result<Option<MediaTypeBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    // deserialize raw string representation
    let typ = match <Option<&str> as Deserialize>::deserialize(deserializer)? {
        Some(typ) => typ,
        None => return Ok(None),
    };

    // RFC 7515 section 4.1.8 allows to strip the `application/` part of
    // the mediatype if the mediatype does not contain any other slashes(`/`)
    match typ.contains('/') {
        // consider this a mediatype in normal format
        true => MediaTypeBuf::from_str(typ)
            .map_err(<D::Error as Error>::custom)
            .map(Some),
        // consider this a mediatype with `application/` removed and append it again
        false => MediaTypeBuf::from_string(format!("application/{}", typ))
            .map_err(<D::Error as Error>::custom)
            .map(Some),
    }
}

fn serialize_mediatype<S>(typ: &Option<MediaTypeBuf>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let typ = match typ.as_ref() {
        Some(typ) => typ,
        // this branch should be unreachable, because Option::None is not serialized
        None => return <Option<&MediaTypeBuf> as Serialize>::serialize(&None, serializer),
    };
    let typ = typ.as_str().split_once('/');
    match typ {
        // if the typ starts with `application/`, strip it if the part after `application/` does not
        // contain any other slashes(`/`)
        Some(("application/", right)) if !right.contains('/') => right.serialize(serializer),
        // if it doesn't start with `application/` or it contains other slashes, keep the original
        _ => typ.serialize(serializer),
    }
}
