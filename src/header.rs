//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
#![allow(missing_docs)]
use alloc::{collections::BTreeSet, string::String};
use core::{marker::PhantomData, ops::Deref};

use mediatype::{MediaType, MediaTypeBuf};
use serde::Deserialize;
use serde_json::{Map, Value};

mod error;
mod formats;
mod parameters;
mod types;
mod value;

#[doc(inline)]
pub use self::{error::Error, types::*, value::*};
use self::{formats::Format, parameters::Parameters};
use crate::{
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm},
    JsonWebKey,
};

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
    pub fn algorithm(&self) -> HeaderValue<&JsonWebSigningAlgorithm> {
        self.parameters.specific.algorithm.as_ref()
    }

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
    pub fn algorithm(&self) -> HeaderValue<&JsonWebEncryptionAlgorithm> {
        self.parameters.specific.algorithm.as_ref()
    }

    pub fn content_encryption_algorithm(&self) -> HeaderValue<&JsonWebContentEncryptionAlgorithm> {
        self.parameters
            .specific
            .content_encryption_algorithm
            .as_ref()
    }
}

struct HeaderDeserializer {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl HeaderDeserializer {
    fn from_values(protected: Value, unprotected: Value) -> Result<Self, Error> {
        // The `protected` and `header` parameters must be a JSON Object
        let protected = match protected {
            Value::Object(object) => object,
            _ => return Err(Error::NotAnObject),
        };
        let unprotected = match unprotected {
            Value::Object(object) => object,
            _ => return Err(Error::NotAnObject),
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
        &'a self,
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
        // Object don't share the same parameters but even if they do, an attacker
        // cannot overwrite protected headers via the unprotected header, because the
        // protected header is searched first.

        if let Some(p) = self.protected.get(field) {
            return Some(V::deserialize(p).map(|v| HeaderValue::Protected(v)));
        }

        if let Some(u) = self.unprotected.get(field) {
            return Some(V::deserialize(u).map(|v| HeaderValue::Unprotected(v)));
        }

        None
    }
}
