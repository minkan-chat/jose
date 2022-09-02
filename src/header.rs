//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
use alloc::{borrow::Cow, format, string::String, vec::Vec};
use core::{ops::Deref, str::FromStr};

use mediatype::{MediaType, MediaTypeBuf};
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

/// A [`JoseHeader`] stores information which are needed in order to process a
/// JWE or JWS.
///
/// A JWE and JWS both contain a header specifying things like the
/// [algorithm](JsonWebAlgorithm). There are two header types:
///
/// * [`Protected`] headers are integrity protected and cannot be changed by an
///   attacker.
/// * [`Unprotected`] headers are NOT integrity protected and can be changed by
///   an attacker.
///
/// If a function or method wants to take a [`JoseHeader`] as an argument, it
/// must specify which of the two types it expects via the generic type `T` at
/// compile time.
///
/// There is also an generic type `A`. This parameter can be used for additional
/// parameters. For details, see [`JoseHeader::additional`].
///
/// Usually, you probably want to use one of the two provided type definitions:
///
/// * [`JweHeader`] for JWE applications
/// * [`JwsHeader`] for JWS applications
// TODO: builder type for jose header
/// [section 4]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
/// [public]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
/// [private]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
// FIXME: can't derive `Hash` because `JsonWebKey` does not implement it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// Only allow deserialization of JoseHeader if T is a valid marker (`HeaderMarker`). If this is not
// set, it would allow deserialization from e.g. `()` which could lead to confusion since it is the
// default type.
#[serde(bound(deserialize = "T: HeaderMarker + Deserialize<'de>, A: Deserialize<'de>"))]
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
        deserialize_with = "deserialize_mediatype",
        default
    )]
    typ: Option<MediaTypeBuf>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        rename = "cty",
        default
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
/// of the signature). Any parameters in this header cannot be trusted since
/// it can be modified by attackers without invalidating the signature.
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
pub struct Jwe<A = ()> {
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
pub struct Jws<A = ()> {
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
pub type JwsHeader<T, A = ()> = JoseHeader<T, Jws<A>>;
/// A [`JoseHeader`] used with Json Web Encryption
pub type JweHeader<T, A = ()> = JoseHeader<T, Jwe<A>>;

// general implementation for protected and unprotected headers in both jwe and
// jws
impl<T, A> JoseHeader<T, A>
where
    T: HeaderMarker,
{
    /// Create a new [`JoseHeaderBuilder`]
    pub fn builder() -> JoseHeaderBuilder<T, ()> {
        JoseHeaderBuilder::<_, ()>::new()
    }

    /// Convert this [`JoseHeader`] to a [`JoseHeaderBuilder`]
    pub fn into_builder(self) -> JoseHeaderBuilder<T, A> {
        JoseHeaderBuilder::from(self)
    }

    /// The [algorithm](JsonWebAlgorithm) used in this JWS or JWE.
    pub fn algorithm(&self) -> JsonWebAlgorithm {
        self.algorithm
    }

    /// Returns a url containing a link to a JSON Web Key Set as defined in
    /// [section 5 of RFC7517].
    ///
    /// This parameter is serialized as `jku` and defined in [section 4.1.2 of
    /// RFC 7517].
    ///
    /// [section 4.1.2 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2>
    /// [section 5 of RFC7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-5>
    // FIXME: use url type instead
    pub fn jwk_set_url(&self) -> Option<&str> {
        self.jwk_set_url.as_deref()
    }

    /// Depending where this [`JoseHeader`] is being used, in JWE it contains
    /// the recipient's public key and in JWS it contains the signer's public
    /// key.
    ///
    /// This parameter is serialized as `jwk` and defined in [section 4.1.3 of
    /// RFC 7515].
    ///
    /// [section 4.1.3 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3>
    pub fn json_web_key(&self) -> Option<&JsonWebKey> {
        self.json_web_key.as_ref()
    }

    /// The identifier of the key used in this JWE or JWS used to give a hint to
    /// recipient.
    ///
    /// It is a case-sensitive string. When used together with a [`JsonWebKey`]
    /// via the [`jwk`](Self::json_web_key) parameter, it is used to match the
    /// [Key ID](JsonWebKey::key_id) of the [`JsonWebKey`].
    ///
    /// This parameter is serialized as `jwk` and defined in [section 4.1.4 of
    /// RFC 7515].
    ///
    /// [section 4.1.4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4>
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// The X.509 URL parameter is an URI (as defined in [RFC 3986]) that refers
    /// to a resource for the X.509 public key certificate or certificate chain
    /// (as defined in [RFC 5280]) of the public key used in this JWE or JWS.
    ///
    /// This parameter is serialized as `x5u` and defined in [section 4.1.5 of
    /// RFC 7515].
    ///
    /// [RFC 3986]: <https://datatracker.ietf.org/doc/html/rfc3986>
    /// [RFC 5280]: <https://datatracker.ietf.org/doc/html/rfc5280>
    /// [section 4.1.5 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5>
    pub fn x509_url(&self) -> Option<&str> {
        self.x509_url.as_deref()
    }

    /// An [`Iterator`] over a X.509 certificate chain that certify the public
    /// key used in this JWE or JWS.
    ///
    /// The first certificate in the [`ExactSizeIterator`] returned by this
    /// method is the PKIX certificate containing the key value as required by
    /// the RFC. Note that this parameter is OPTIONAL and if not present, this
    /// [`ExactSizeIterator`] will be empty ([`next`](Iterator::next) will be
    /// [`None`] and [`len`](ExactSizeIterator::len) will be `0`).
    ///
    /// Each [`Item`](Iterator::Item) will be the byte representation of a
    /// DER-encoded X.509 certificate. This parameter works the same as
    /// [`JsonWebKey::x509_certificate_chain`].
    ///
    /// This parameter is serialized as `x5u` and defined in [section 4.1.5 of
    /// RFC 7515].
    ///
    /// [section 4.1.5 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5>
    pub fn x509_certificate_chain(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.x509_certificate_chain.iter().map(Deref::deref)
    }

    /// This parameter is the SHA-1 hash of the DER-encoded X.509 certificate
    /// (X.509 Certificate SHA-1 Thumbprint).
    ///
    /// # Warning: Cryptographically broken!
    ///
    /// TL;DR: check if you can use the [SHA-256
    /// thumbprint](Self::x509_certificate_sha256_thumbprint) instead.
    ///
    /// The following text is taken from the [`sha1`] crate: \
    /// The SHA-1 hash function should be considered cryptographically broken
    /// and unsuitable for further use in any security critical capacity, as it
    /// is [practically vulnerable to chosen-prefix collisions](https://sha-mbles.github.io/).
    ///
    /// This parameter is serialized as `x5t` and defined in [section 4.1.7 of
    /// RFC 7515].
    ///
    /// [section 4.1.7 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7>
    // replace the hardcoded output size with the Sha1::OutputsizeUser value then
    // they use const generics
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&[u8; 20]> {
        self.x509_certificate_sha1_thumbprint.as_ref()
    }

    /// This parameter is the SHA-256 hash of the DER-encoded X.509 certificate
    /// (X.509 Certificate SHA-256 Thumbprint).
    ///
    /// This parameter is serialized as `x5t#S256` and defined in [section 4.1.8
    /// of RFC 7515].
    ///
    /// [section 4.1.8 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8>
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&[u8; 32]> {
        self.x509_certificate_sha256_thumbprint.as_ref()
    }

    /// The Type parameter is used to declare the [media type] of this
    /// complete JWE or JWS.
    ///
    /// This parameter is serialized as `typ` and defined in [section 4.1.9 of
    /// RFC 7515].
    ///
    /// # Example
    ///
    /// When a [`JoseHeader`] is being used with a JSON Web Token and this
    /// parameter is set, it is recommended that this type will be
    /// [`application`]`/`[`jwt`] as defined in [section 5.1 of RFC 7519].
    ///
    /// [media type]: <https://www.iana.org/assignments/media-types>
    /// [section 4.1.9 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9>
    /// [`application`]: <mediatype::names::APPLICATION>
    /// [`jwt`]: <mediatype::names::JWT>
    /// [section 5.1 of RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519#section-5.1>
    pub fn typ(&self) -> Option<MediaType<'_>> {
        self.typ.as_ref().map(|f| f.to_ref())
    }

    /// The Content Type parameter is used to declare the [media type] of the
    /// payload of a JWE or JWS.
    ///
    /// This parameter is serialized as `cty` and defined in [section 4.1.10 of
    /// RFC 7515].
    ///
    /// # Example
    ///
    /// When a [`JoseHeader`] is being used with a JSON Web Token and nested
    /// encryption or signing is employed, this parameter must be present and be
    /// set to [`application`]`/`[`jwt`] as defined by [section 5.2 of RFC
    /// 7519].
    ///
    /// [media type]: <https://www.iana.org/assignments/media-types>
    /// [section 4.1.10 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10>
    /// [`application`]: <mediatype::names::APPLICATION>
    /// [`jwt`]: <mediatype::names::JWT>
    /// [section 5.2 of RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519#section-5.2>
    pub fn content_type(&self) -> Option<MediaType<'_>> {
        self.typ.as_ref().map(|f| f.to_ref())
    }

    /// Additional parameters in this [`JoseHeader`] defined by the generic type
    /// `A`.
    ///
    /// Note that there are three classes of parameters in a [`JoseHeader`] as
    /// defined by [section 4 of RFC 7515]:
    ///
    /// * Registered Header Parameters: Parameters whose name is registered in
    ///   the [IANA `JSON Web Signature and Encryption Header Parameters`
    ///   registry] as defined in [section 4.1 of RFC 7515].
    /// * Public Header Parameters: Parameters whose name is collision resistant
    ///   as defined in [section 4.2 of RFC 7515].
    /// * Private Header Parameters: Parameters whose use is limited to closed
    ///   environments where one party controlls both the producer and consumer
    ///   and defines how to process these parameters as defined in [section 4.3
    ///   of RFC 7515].
    ///
    /// We strongly advise you to only use Public Header Parameters in your
    /// additional parameters because use of other parameters can introduce
    /// breakage which is not covered by a major semver change.
    ///
    /// If there are parameters that are in the [IANA `JSON Web Signature and
    /// Encryption Header Parameters` registry] and not supported by this
    /// implementation, please open an issue and consider submitting a pull
    /// request instead.
    ///
    /// An example of such potential breakage would be if you were to introduce
    /// a fictional `rep` (recipient) parameter which is an untyped
    /// [`String`]. If a specification now introduced the same `rep` parameter
    /// but were to add more constraints on the format of the [`String`] -- for
    /// example, requiring it to be an URL -- and our library implemented
    /// this parameter, deserialization would fail, because your application
    /// put "invalid" data in the `rep` header which is catched by _our_
    /// implementation of this parameter.
    ///
    /// # Example
    ///
    /// In order to use additional parameters in a [`JoseHeader`], define a
    /// container:
    ///
    /// ```
    /// # use serde::{Serialize, Deserialize};
    /// # use jose::header::{JwsHeader, JweHeader};
    /// #[derive(Deserialize, Serialize)]
    /// struct MyAdditionalParameters {
    ///     // Use a collision resistant name. In this case, make it collision
    ///     // resistant by using a domain you control:
    ///     #[serde(rename = "http://my-domain.com/rep")]
    ///     rep: Option<String>,
    /// }
    ///
    /// // Use these two type definitions instead of the default ones.
    /// type MyJwsHeader<T> = JwsHeader<T, MyAdditionalParameters>;
    /// type MyJweHeader<T> = JweHeader<T, MyAdditionalParameters>;
    /// ```
    ///
    /// [section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
    /// [IANA `JSON Web Signature and Encryption Header Parameters` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters>
    /// [section 4.1 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1>
    /// [section 4.2 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
    /// [section 4.3 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
    pub fn additional(&self) -> &A {
        &self.additional
    }
}

// implementation for protected headers in both jwe and jws
impl<A> JoseHeader<Protected, A> {
    /// An [`Iterator`] over the critical header parameters in this
    /// [`JoseHeader`].
    ///
    /// Note that this parameter is OPTIONAL and if not present, this
    /// [`ExactSizeIterator`] will be empty ([`next`](Iterator::next) will be
    /// [`None`] and [`len`](ExactSizeIterator::len) will be `0`).
    ///
    /// Each [`Item`](Iterator::Item`) will be the serialized form of the header
    /// parameter (e.g. `cty` instead of
    /// [`content_type`](JoseHeader::content_type)). Every
    // FIXME: link to Policy method that validates critical header parameters
    /// [`Item`](Iterator::Item) MUST be understood for this JWE or JWS to be
    /// considered valid.
    ///
    /// This parameter is serialized as `crit` and is defined in [section 4.1.11
    /// of RFC 7515].
    ///
    /// Note that this parameter can only appear in [`Protected`] headers.
    ///
    /// [section 4.1.11 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11>
    pub fn critical_headers(&self) -> impl ExactSizeIterator<Item = &str> {
        self.header_type.critical_headers.iter().map(Deref::deref)
    }
}

// implementation for unprotected headers in both jwe and jws
impl<A> JoseHeader<Unprotected, A> {
    // Empty.
}

// implementation for protected and unprotected headers in jws
impl<T, A> JwsHeader<T, A>
where
    T: HeaderMarker,
{
    // Empty.
}

// implementation for protected headers in jws
impl<A> JwsHeader<Protected, A> {
    /// This header parameter defines if the payload of a JWS is
    /// base64url-encoded or not.
    ///
    /// Encoding the payload in base64url is unnecessary in some cases. One such
    /// case would be detached content as defined in [Appendix F of RFC 7515].
    ///
    /// This parameter is serialized as `b64` and is defined in [section 3 of
    /// RFC 7797].
    ///
    /// Note that this parameter can only appear in JWS within [`Protected`]
    /// headers.
    ///
    /// [section 3 of RFC 7797]: <https://datatracker.ietf.org/doc/html/rfc7797#section-3>
    /// [Appendix F of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#appendix-F>
    pub fn payload_base64_url_encoded(&self) -> bool {
        self.additional.payload_base64_url_encoded
    }
}

// implementation for unprotected headers in jws
impl<A> JwsHeader<Unprotected, A> {
    // Empty.
}

// implementation for protected and unprotected headers in jwe
impl<T, A> JweHeader<T, A>
where
    T: HeaderMarker,
{
    // Empty.
}

// implementation for protected headers in jwe
impl<A> JweHeader<Protected, A> {
    // Empty.
}

// implementation for unprotected headers in jwe
impl<A> JweHeader<Unprotected, A> {
    // Empty.
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

    let typ = match <Option<Cow<'_, str>> as Deserialize>::deserialize(deserializer)? {
        Some(typ) => typ,
        None => return Ok(None),
    };

    // RFC 7515 section 4.1.8 allows to strip the `application/` part of
    // the mediatype if the mediatype does not contain any other slashes(`/`)
    match typ.contains('/') {
        // consider this a mediatype in normal format
        true => MediaTypeBuf::from_str(typ.as_ref())
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
