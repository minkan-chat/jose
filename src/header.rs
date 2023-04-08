//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
};
use core::{marker::PhantomData, ops::Deref};

use mediatype::{MediaType, MediaTypeBuf};
use serde::Deserialize;
use serde_json::{Map, Value};

mod builder;
mod error;
mod formats;
mod parameters;
mod types;
mod value;

#[doc(inline)]
pub use self::{
    builder::{JoseHeaderBuilder, JoseHeaderBuilderError},
    error::Error,
    types::*,
    value::*,
};
use self::{formats::Format, parameters::Parameters};
use crate::{
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    JsonWebKey,
};

/// A [`JoseHeader`] is primarily used to specify how a JSON Web Signature or
/// JSON Web Encryption should be processed.
///
/// Besides the [`algorithm`](JoseHeader::algorithm) used for the cryptographic
/// primitives, it can also store additional metadata that should not be part of
/// the payload.
/// For example, the [`typ`](JoseHeader::typ) parameter may be used to specify a
/// content type for the payload.
///
/// # Structure
///
/// A [`JoseHeader`] may be a bit different, depending where it is being used.
/// Therefore, [`JoseHeader<F, T>`] has two generic types that define where and
/// how exactly it is being used. `F` defines the [`Format`] that this
/// [`JoseHeader`] is being used in. `T` defines whether the [`JoseHeader`] is
/// part of a [JSON Web Signature][Jws] or [JSON Web Encryption][Jwe].
///
/// A [`JoseHeader`] can store parameters in two ways:
///
/// * [protected](HeaderValue::Protected): Parameters stored in the protected
///   part of a [`JoseHeader`] can not be modified without the knowledge of the
///   cryptographic key that was used to protected the payload.
///
/// * [unprotected](HeaderValue::Unprotected): Parameters stored in the
///   unprotected part of a [`JoseHeader`] **can** be modified by anybody and
///   changes cannot be detected. You therefore cannot rely or trust them.
///
/// Since most parameters are allowed in both of the two header parts, each
/// parameter is wrapped in a [`HeaderValue<T>`] that specifies the part in
/// which the paramter is stored.
///
/// # Parameter classes
///
/// [Section 4 of RFC 7515] defines three classes of header parameters:
///
/// * [Registered header parameters]: these parameters are registerd in the
///   [IANA `JSON Web Signature and Encryption Header Parameters` registry].
///   Most of them are implemented by this library and can be directly accessed
///   via the methods on [`JoseHeader`]. If you find a registered parameter you
///   need missing, you are welcome to open an issue or even better a pull
///   request to support it.
///
/// * [Public header parameters]: these parameters are not registered but use a
///   "Collision-Resistant Name" (e.g. they are prefixed by a domain you
///   control) as defined in [section 2 of RFC 7515]. You may access them using
///   [`JoseHeader::additional`].
///
/// * [Private header parameters]: these parameters are not registered either
///   but do not use a "Collisin-Resistant Name" and are therefore subject to
///   collision. You can also use them via [`JoseHeader::additional`] but their
///   use is not recommended and if new paramters are registered that collide
///   with a private parameter, your implementation may break.
///
/// # Examples
///
///
/// ```
/// use jose::{
///     format::Compact,
///     header::{HeaderValue, JoseHeader, Jws},
///     jwa::Hmac,
/// };
///
/// // we are going to build a `JoseHeader` for a `Compact` `Jws`
/// let header = JoseHeader::<Compact, Jws>::builder()
///     // we set the `alg` header parameter as an unprotected parameter
///     .algorithm(HeaderValue::Unprotected(Hmac::Hs256.into()))
///     // we set the `kid` header parameter as an protected parameter
///     .key_identifier(Some(HeaderValue::Protected("key-1".to_string())))
///     .build()
///     .unwrap();
///
/// assert_eq!(
///     header.algorithm(),
///     HeaderValue::Unprotected(&Hmac::Hs256.into())
/// );
/// assert_eq!(
///     header.key_identifier(),
///     Some(HeaderValue::Protected("key-1"))
/// );
/// ```
///
/// [section 2 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-2>
/// [Section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
/// [IANA `JSON Web Signature and Encryption Header Parameters` registry]: <https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters>
/// [Registered header parameters]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1>
/// [Public header parameters]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.2>
/// [Private header parameters]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.3>
#[derive(Debug)]
pub struct JoseHeader<F, T> {
    parameters: Parameters<T>,
    // marker for the format (compact, json general, json flattened)
    _format: PhantomData<F>,
}

impl<F, T> JoseHeader<F, T>
where
    F: Format,
    T: Type,
{
    /// Build a new [`JoseHeader`].
    pub fn builder() -> JoseHeaderBuilder<F, T> {
        JoseHeaderBuilder::default()
    }

    /// Modify this [`JoseHeader`] by turning it back into a
    /// [`JoseHeaderBuilder`].
    pub fn into_builder(self) -> JoseHeaderBuilder<F, T> {
        JoseHeaderBuilder::from_header(self)
    }

    /// Returns a url containing a link to a JSON Web Key Set as defined in
    /// [section 5 of RFC 7517].
    ///
    /// This parameter is serialized as `jku` and defined in [section 4.1.2 of
    /// RFC 7515].
    ///
    /// [section 4.1.2 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2>
    /// [section 5 of RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517#section-5>
    // FIXME: use url type instead
    pub fn jwk_set_url(&self) -> Option<HeaderValue<&str>> {
        self.parameters
            .jwk_set_url
            .as_ref()
            .map(HeaderValue::as_deref)
    }

    /// Depending where this [`JoseHeader`] is being used, in JWE it contains
    /// the recipient's public key and in JWS it contains the signer's public
    /// key.
    ///
    /// This parameter is serialized as `jwk` and defined in [section 4.1.3 of
    /// RFC 7515].
    ///
    /// [section 4.1.3 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3>
    pub fn json_web_key(&self) -> Option<HeaderValue<&JsonWebKey<Value>>> {
        self.parameters
            .json_web_key
            .as_ref()
            .map(HeaderValue::as_ref)
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
    pub fn key_identifier(&self) -> Option<HeaderValue<&str>> {
        self.parameters.key_id.as_ref().map(HeaderValue::as_deref)
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
    pub fn x509_url(&self) -> Option<HeaderValue<&str>> {
        self.parameters.x509_url.as_ref().map(HeaderValue::as_deref)
    }

    /// An [`Iterator`] over a X.509 certificate chain that certify the public
    /// key used in this JWE or JWS.
    ///
    /// The first certificate in the [`Iterator`] returned by this method is the
    /// PKIX certificate containing the key value as required by the RFC.
    ///
    /// Each [`Item`](Iterator::Item) will be the byte representation of a
    /// DER-encoded X.509 certificate. This parameter works the same as
    /// [`JsonWebKey::x509_certificate_chain`].
    ///
    /// This parameter is serialized as `x5u` and defined in [section 4.1.6 of
    /// RFC 7515].
    ///
    /// [section 4.1.6 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6>
    pub fn x509_certificate_chain(&self) -> Option<HeaderValue<impl Iterator<Item = &[u8]>>> {
        self.parameters
            .x509_certificate_chain
            .as_ref()
            .map(HeaderValue::as_deref)
            .map(|value| value.map(|certs| certs.iter().map(Deref::deref)))
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
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<HeaderValue<&[u8; 20]>> {
        self.parameters
            .x509_certificate_sha1_thumbprint
            .as_ref()
            .map(HeaderValue::as_ref)
    }

    /// This parameter is the SHA-256 hash of the DER-encoded X.509 certificate
    /// (X.509 Certificate SHA-256 Thumbprint).
    ///
    /// This parameter is serialized as `x5t#S256` and defined in [section 4.1.8
    /// of RFC 7515].
    ///
    /// [section 4.1.8 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8>
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<HeaderValue<&[u8; 32]>> {
        self.parameters
            .x509_certificate_sha256_thumbprint
            .as_ref()
            .map(HeaderValue::as_ref)
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
    pub fn typ(&self) -> Option<HeaderValue<MediaType<'_>>> {
        self.parameters
            .typ
            .as_ref()
            .map(|value| value.as_ref().map(MediaTypeBuf::to_ref))
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
    pub fn content_type(&self) -> Option<HeaderValue<MediaType<'_>>> {
        self.parameters
            .content_type
            .as_ref()
            .map(|value| value.as_ref().map(MediaTypeBuf::to_ref))
    }

    /// Get additional parameters by their serialized parameter name.
    ///
    /// Note: Parameters that are understood by this implementation (receivable
    /// via the method on [`JoseHeader`]) will return [`None`]. Use the
    /// appropriate method instead.
    pub fn additional(&self, parameter_name: impl AsRef<str>) -> Option<HeaderValue<&Value>> {
        self.parameters
            .additional
            .get(parameter_name.as_ref())
            .map(|v| v.as_ref())
    }

    /// The Critical Header parameter is used to declare headers that must be
    /// understood by an implementation.
    ///
    /// It is an [`Iterator`] over the parameter names of critical headers in
    /// this [`JoseHeader`]. If there are no headers marked as critical, this
    /// [`Iterator`] will be empty.
    ///
    /// This parameter is serialized as `crit` and defined in [section 4.1.11 of
    /// RFC 7515].
    ///
    /// Note: Header names listed in this parameter have to be present and the
    /// [`JoseHeader`] is considered invalid otherwise.
    ///
    /// Note: This header parameter is always integrity protected.
    ///
    /// [section 4.1.11 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11>
    pub fn critical_headers(&self) -> impl Iterator<Item = &'_ str> {
        self.parameters
            .critical_headers
            .iter()
            .flatten()
            .map(Deref::deref)
    }
}

impl<F> JoseHeader<F, Jws>
where
    F: Format,
{
    /// The [signing algorithm](JsonWebSigningAlgorithm) used to create the
    /// signature for the JWS this [`JoseHeader`] is contained in.
    ///
    /// This parameter is serialized as `alg` and defined in [section 4.1.1 of
    /// RFC 7515].
    ///
    /// [section 4.1.1 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1>
    pub fn algorithm(&self) -> HeaderValue<&JsonWebSigningAlgorithm> {
        self.parameters.specific.algorithm.as_ref()
    }

    /// Whether the payload is being base64url encoded or not.
    ///
    /// This parameter is serialized as `b64` and defined in [section 3 of RFC
    /// 7797].
    ///
    /// Note: This header parameter is always integrity protected.
    ///
    /// Note: This header parameter is OPTIONAL and has a default value of
    /// `true`.
    ///
    /// [section 3 of RFC 7797]: <https://datatracker.ietf.org/doc/html/rfc7797#section-3>
    pub fn payload_base64_url_encoded(&self) -> bool {
        self.parameters
            .specific
            .payload_base64_url_encoded
            .unwrap_or(true)
    }
}

impl<F> JoseHeader<F, Jwe>
where
    F: Format,
{
    /// The [encryption algorithm][JsonWebEncryptionAlgorithm] used to
    /// encryption the content encryption key (CEK).
    ///
    /// This parameter is serialized as `alg` and defined in [section 4.1.1 of
    /// RFC 7516].
    ///
    /// [section 4.1.1 of RFC 7516]: <https://datatracker.ietf.org/doc/html/rfc7516/#section-4.1.1>
    pub fn algorithm(&self) -> HeaderValue<&JsonWebEncryptionAlgorithm> {
        self.parameters.specific.algorithm.as_ref()
    }

    /// The [encryption algorithm](JsonWebContentEncryptionAlgorithm) used to
    /// encryption the payload of a JWE.
    ///
    /// This parameter is serialized as `enc` and defined in [section 4.1.2 of
    /// RFC 7516].
    ///
    /// [section 4.1.2 of RFC 7516]: <https://datatracker.ietf.org/doc/html/rfc7516/#section-4.1.2>
    pub fn content_encryption_algorithm(&self) -> HeaderValue<&JsonWebContentEncryptionAlgorithm> {
        self.parameters
            .specific
            .content_encryption_algorithm
            .as_ref()
    }
}

impl<F, T> JoseHeader<F, T>
where
    F: Format,
    T: Type,
{
    /// Build a JoseHeader from its `header` and `protected` part.
    ///
    /// Note: The `protected` part must already be base64 decoded.
    pub(crate) fn from_values(
        protected: Option<Map<String, Value>>,
        unprotected: Option<Map<String, Value>>,
    ) -> Result<Self, Error> {
        let de = HeaderDeserializer::from_values(protected, unprotected)?;
        let (specific, mut de) = T::from_deserializer(de).map_err(|(e, _)| e)?;
        Ok(Self {
            parameters: Parameters {
                critical_headers: de
                    .deserialize_field("crit")
                    .transpose()?
                    .map(|v| v.protected().ok_or(Error::ExpectedProtected))
                    .transpose()?
                    .map(|v: BTreeSet<_>| {
                        // RFC 7515
                        // `crit` must not be an empty list,
                        // must not contain header names specified by the specification
                        // FIXME: consider forbidden headers that are `Format` specific.
                        if v.is_empty() {
                            return Err(Error::EmptyCriticalHeaders);
                        }
                        for forbidden in T::forbidden_critical_headers() {
                            if v.contains(*forbidden) {
                                return Err(Error::ForbiddenHeader(forbidden.to_string()));
                            }
                        }
                        Ok(v)
                    })
                    .transpose()?,
                jwk_set_url: de.deserialize_field("jku").transpose()?,
                json_web_key: de.deserialize_field("jwk").transpose()?,
                key_id: de.deserialize_field("kid").transpose()?,
                x509_url: de.deserialize_field("x5u").transpose()?,
                x509_certificate_chain: de.deserialize_field("x5c").transpose()?,
                x509_certificate_sha1_thumbprint: de.deserialize_field("x5t").transpose()?,
                x509_certificate_sha256_thumbprint: de.deserialize_field("x5t#S256").transpose()?,
                typ: de.deserialize_field("typ").transpose()?,
                content_type: de.deserialize_field("cty").transpose()?,
                specific,
                additional: de.additional(),
            },
            _format: PhantomData,
        })
    }

    /// Returns `Result<(Option<Protected>, Option<Unprotected>), Error>`
    #[allow(clippy::type_complexity)]
    pub(crate) fn into_values(
        self,
    ) -> Result<(Option<Map<String, Value>>, Option<Map<String, Value>>), Error> {
        let parameters = self.parameters;

        // use the existing Map with additional parameters. Parameters that collide with
        // names understood by this library are replaced.
        let mut collected_parameters = parameters.additional;

        // insert crit header only if it is some and non empty as per RFC
        if let Some(crit) = parameters.critical_headers {
            if !crit.is_empty() {
                collected_parameters.insert(
                    "crit".to_string(),
                    HeaderValue::Protected(serde_json::to_value(crit)?),
                );
            }
        } else {
            collected_parameters.remove("crit");
        }

        // FIXME: optimize this code in a way that there are not this many inserts
        macro_rules! insert {
            ($($name:literal: $value:expr),+,) => {
                $(if let Some(value) = $value {
                    collected_parameters.insert(
                        $name.to_string(),
                        value.map(serde_json::to_value).transpose()?,
                    );
                } else {
                    collected_parameters.remove($name);
                })+
            };
        }
        insert! {
            "jku": parameters.jwk_set_url,
            "jwk": parameters.json_web_key,
            "kid": parameters.key_id,
            "x5u": parameters.x509_url,
            "x5c": parameters.x509_certificate_chain,
            "x5t": parameters.x509_certificate_sha1_thumbprint,
            "x5t#S256": parameters.x509_certificate_sha256_thumbprint,
            "typ": parameters.typ,
            "cty": parameters.content_type,
        }

        let mut protected = Map::new();
        let mut unprotected = Map::new();
        for (key, value) in collected_parameters
            .into_iter()
            .chain(parameters.specific.into_map()?)
        {
            match value {
                HeaderValue::Protected(value) => protected.insert(key, value),
                HeaderValue::Unprotected(value) => unprotected.insert(key, value),
            };
        }

        let protected = match protected.is_empty() {
            true => None,
            false => Some(protected),
        };

        let unprotected = match unprotected.is_empty() {
            true => None,
            false => Some(unprotected),
        };

        Ok((protected, unprotected))
    }
}

/// An implementation detail for [`JoseHeader`]
#[derive(Debug)]
pub struct HeaderDeserializer {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl HeaderDeserializer {
    /// Prepare the deserialize for deserialization and run a few checks
    fn from_values(
        protected: Option<Map<String, Value>>,
        unprotected: Option<Map<String, Value>>,
    ) -> Result<Self, Error> {
        // ensure that if the header is present, it actually contains some members as
        // per section 7.2.1 of RFC 7515
        if let Some(ref p) = protected {
            if p.is_empty() {
                return Err(Error::EmptyHeader);
            }
        }
        if let Some(ref u) = unprotected {
            if u.is_empty() {
                return Err(Error::EmptyHeader);
            }
        }

        let (protected, unprotected) = match (protected, unprotected) {
            (Some(protected), Some(unprotected)) => (protected, unprotected),
            (Some(protected), None) => (protected, Map::new()),
            (None, Some(unprotected)) => (Map::new(), unprotected),
            (None, None) => return Err(Error::NoHeader),
        };

        let protected_keys: BTreeSet<&str> = protected.keys().map(Deref::deref).collect();
        let unprotected_keys: BTreeSet<&str> = unprotected.keys().map(Deref::deref).collect();

        // the members of `protected` and `header` must be disjoint, because otherwise
        // an implementation must decide which header type takes priority
        if !protected_keys.is_disjoint(&unprotected_keys) {
            return Err(Error::NotDisjoint);
        }

        Ok(Self {
            protected,
            unprotected,
        })
    }

    fn deserialize_field<'a, 'de, V>(
        &'a mut self,
        field: &'a str,
    ) -> Option<Result<HeaderValue<V>, serde_json::Error>>
    where
        V: Deserialize<'de>,
        'a: 'de,
    {
        // Security
        //
        // This method first looks at the `protected` header and if the requested field
        // isn't in there, it looks in the `header` parameter (which is not integrity
        // protected). A `HeaderDeserializer` should always ensure that the inner JSON
        // Objects don't share the same parameters but even if they do, an attacker
        // cannot overwrite protected headers via the unprotected header, because the
        // protected header is searched first.

        if let Some(p) = self.protected.remove(field) {
            debug_assert_eq!(self.unprotected.remove(field), None);
            return Some(V::deserialize(p).map(|v| HeaderValue::Protected(v)));
        }

        if let Some(u) = self.unprotected.remove(field) {
            debug_assert_eq!(self.protected.remove(field), None);
            return Some(V::deserialize(u).map(|v| HeaderValue::Unprotected(v)));
        }

        None
    }

    fn additional(self) -> BTreeMap<String, HeaderValue<Value>> {
        self.protected
            .into_iter()
            .map(|(field, value)| (field, HeaderValue::Protected(value)))
            .chain(
                self.unprotected
                    .into_iter()
                    .map(|(field, value)| (field, HeaderValue::Unprotected(value))),
            )
            .collect()
    }
}
