//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
use alloc::{borrow::Cow, format, string::String, vec::Vec};
use core::{hash::Hash, ops::Deref, str::FromStr};

use hashbrown::HashSet;
use mediatype::{MediaType, MediaTypeBuf};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    jwk::serde_impl::{self, Base64DerCertificate},
    sealed::Sealed,
    JsonWebKey,
};

mod builder;
mod serde_;
#[doc(inline)]
pub use builder::{BuilderError, JoseHeaderBuilder};

use self::serde_::HeaderReprOwned;

/// A [`JoseHeader`] stores information which are needed in order to process a
/// JWE or JWS.
///
/// JWE and JWS both contain a header specifying things like the
/// [algorithm](crate::jwa::JsonWebAlgorithm). There are two header types:
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
/// The generic type `U` specifies if a [`JoseHeader`] is for JSON Web
/// Encryption ([`Jwe`]) or for JSON Web Signatures ([`Jws`]). There are two
/// type alias provided for you:
///
/// * [`JwsHeader<T, A>`]
/// * [`JweHeader<T, A>`]
///
/// The generic type `T` is the same as in [`JoseHeader<T, U>`] and is either
/// [`Protected`] or [`Unprotected`]. The generic type `A` is for additional
/// header parameters defined by you. `A`'s default type is `()` which means if
/// you don't specify it, there are no additional header parameters. You can
/// read more about how to use additional header parameters in [`JwsHeader<T,
/// A>::additional`].
///
/// # Examples
///
/// Build a protected header for a JSON Web Signature:
///
/// ```
/// # use jose::header::BuilderError;
/// # fn main() -> Result<(), BuilderError> {
/// use jose::{jwa::{EcDSA, JsonWebSigningAlgorithm}, header::JwsHeader};
/// use mediatype::{MediaTypeBuf, MediaType, names};
///
/// let jws_header = JwsHeader::builder()
///     .protected()
///     .algorithm(EcDSA::Es256)
///     // set some parameters
///     .typ(Some(MediaTypeBuf::new(names::APPLICATION, names::JOSE)))
///     .content_type(Some(MediaTypeBuf::new(names::TEXT, names::PLAIN)))
///     // build the header
///     .build()?;
///
/// assert_eq!(jws_header.algorithm(), &JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256));
/// assert_eq!(jws_header.typ(), Some(MediaType::parse("application/jose").unwrap()));
/// assert_eq!(jws_header.content_type(), Some(MediaType::parse("text/plain").unwrap()));
/// # Ok(())
/// # }
// FIXME: can't derive `Hash` because `JsonWebKey` does not implement it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JoseHeader<T = (), U = ()> {
    // Shared parameters between JWS and JWE
    inner: HeaderReprOwned<T, U>,
}

/// A marker trait which specifies where a [`JoseHeader`] can appear.
///
/// For details, see [`Protected`] and [`Unprotected`].
pub trait HeaderMarker: Sealed {}
/// A marker trait which specifies if a [`JoseHeader`] can be used in JSON Web
/// Encryption or JSON Web Signatures.
///
/// For details, see [`Jwe`] and [`Jws`].
pub trait TypeMarker: Sealed {}

/// Marker struct for a [`JoseHeader`] that is integrity protected (part of the
/// signature).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Protected {
    /// `crit` parameter as defined in section 4.1.11 of JWS and section 4.1.13
    /// of JWE
    //#[serde(rename = "crit", default, skip_serializing_if = "Vec::is_empty")]
    critical_headers: HashSet<String>,
}

/// Marker struct for a [`JoseHeader`] that is not integrity protected (not part
/// of the signature). Any parameters in this header cannot be trusted since
/// it can be modified by attackers without invalidating the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unprotected {
    // Empty.
}

impl Sealed for Protected {}
impl Sealed for Unprotected {}
impl HeaderMarker for Protected {}
impl HeaderMarker for Unprotected {}
impl<A> Sealed for Jws<A> {}
impl<A> Sealed for Jwe<A> {}
impl<A> TypeMarker for Jws<A> {}
impl<A> TypeMarker for Jwe<A> {}

/// Header parameters that are specific to encryption
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Jwe<A = ()> {
    algorithm: JsonWebEncryptionAlgorithm,
    // TODO: JWE Headers
    //#[serde(rename = "enc")]
    content_encryption_algorithm: JsonWebContentEncryptionAlgorithm,
    //#[serde(flatten)]
    additional: A,
}

/// Header parameters that are specific to signatures
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Jws<A = ()> {
    algorithm: JsonWebSigningAlgorithm,
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
    payload_base64_url_encoded: Option<bool>,
    //#[serde(flatten)]
    additional: A,
}

/// A [`JoseHeader`] used with Json Web Signatures
pub type JwsHeader<T = (), A = ()> = JoseHeader<T, Jws<A>>;
/// A [`JoseHeader`] used with Json Web Encryption
pub type JweHeader<T = (), A = ()> = JoseHeader<T, Jwe<A>>;

// general implementation for protected and unprotected headers in both jwe and
// jws
impl<T, A> JoseHeader<T, A>
where
    T: HeaderMarker,
    A: TypeMarker,
{
    /// Returns a url containing a link to a JSON Web Key Set as defined in
    /// [section 5 of RFC 7517].
    ///
    /// This parameter is serialized as `jku` and defined in [section 4.1.2 of
    /// RFC 7515].
    ///
    /// [section 4.1.2 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2>
    /// [section 5 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-5>
    // FIXME: use url type instead
    pub fn jwk_set_url(&self) -> Option<&str> {
        self.inner.jwk_set_url.as_deref()
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
        self.inner.json_web_key.as_ref()
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
        self.inner.key_id.as_deref()
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
        self.inner.x509_url.as_deref()
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
        self.inner.x509_certificate_chain.iter().map(Deref::deref)
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
        self.inner.x509_certificate_sha1_thumbprint.as_ref()
    }

    /// This parameter is the SHA-256 hash of the DER-encoded X.509 certificate
    /// (X.509 Certificate SHA-256 Thumbprint).
    ///
    /// This parameter is serialized as `x5t#S256` and defined in [section 4.1.8
    /// of RFC 7515].
    ///
    /// [section 4.1.8 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8>
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&[u8; 32]> {
        self.inner.x509_certificate_sha256_thumbprint.as_ref()
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
        self.inner.typ.as_ref().map(|f| f.to_ref())
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
        self.inner.content_type.as_ref().map(|f| f.to_ref())
    }
}

impl JwsHeader {
    /// Create a [`JoseHeaderBuilder`] to build a [`JwsHeader`].
    pub fn builder() -> JoseHeaderBuilder<(), Jws> {
        JoseHeaderBuilder::default()
    }
}
impl<T, A> JwsHeader<T, A>
where
    T: HeaderMarker,
{
    /// Convert this [`JwsHeader`] back to a [`JoseHeaderBuilder`].
    pub fn into_builder(self) -> JoseHeaderBuilder<T, Jws<A>, A> {
        self.into()
    }

    /// The [`JsonWebSigningAlgorithm`] used in this [`Jws`].
    pub fn algorithm(&self) -> &JsonWebSigningAlgorithm {
        &self.inner.additional.algorithm
    }

    /// Additional parameters in this [`JoseHeader`] defined by the generic type
    /// `A` in [`Jws<A>`].
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
    /// request.
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
        &self.inner.additional.additional
    }
}

impl<T, A> JweHeader<T, A>
where
    T: HeaderMarker,
{
    /// Convert this [`JwsHeader`] back to a [`JoseHeaderBuilder`].
    pub fn into_builder(self) -> JoseHeaderBuilder<T, Jwe<A>, A> {
        self.into()
    }

    /// The [`JsonWebEncryptionAlgorithm`] used in this [`Jwe`] to encrypt the
    /// content encryption key (CEK).
    pub fn algorithm(&self) -> &JsonWebEncryptionAlgorithm {
        &self.inner.additional.algorithm
    }

    /// The [`JsonWebContentEncryptionAlgorithm`] used to encrypt the payload of
    /// this [`Jwe`].
    pub fn content_encryption_algorithm(&self) -> &JsonWebContentEncryptionAlgorithm {
        &self.inner.additional.content_encryption_algorithm
    }

    /// Additional parameters in this [`JoseHeader`] defined by the generic type
    /// `A` in [`Jwe<A>`].
    ///
    /// This method is equivalent to [`JwsHeader<T, A>::additional`] but for
    /// [`Jwe<A>`] instead of [`Jws<A>`]. See [`JwsHeader<T, A>::additional`]
    /// for details.
    pub fn additional(&self) -> &A {
        &self.inner.additional.additional
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
        self.inner
            .header_type
            .critical_headers
            .iter()
            .map(Deref::deref)
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
    /// Note that this parameter can only appear in [`Jws`] within [`Protected`]
    /// headers.
    ///
    /// [section 3 of RFC 7797]: <https://datatracker.ietf.org/doc/html/rfc7797#section-3>
    /// [Appendix F of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#appendix-F>
    pub fn payload_base64_url_encoded(&self) -> bool {
        self.inner
            .additional
            .payload_base64_url_encoded
            .unwrap_or(true)
    }
}

// implementation for unprotected headers in jws
impl<A> JwsHeader<Unprotected, A> {
    // Empty.
}

impl JweHeader {
    /// Create a [`JoseHeaderBuilder`] to build a [`JweHeader`].
    pub fn builder() -> JoseHeaderBuilder<(), Jwe> {
        JoseHeaderBuilder::default()
    }
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

impl<T, A> AsRef<A> for JwsHeader<T, A> {
    fn as_ref(&self) -> &A {
        &self.inner.additional.additional
    }
}

impl<T, A> AsRef<A> for JweHeader<T, A> {
    fn as_ref(&self) -> &A {
        &self.inner.additional.additional
    }
}
