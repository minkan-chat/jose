use hashbrown::HashSet;
use serde::{de::Error as _, ser::Error as _};
use serde_json::{Map, Value};

use super::*;
use crate::jwa::{JsonWebEncryptionAlgorithm, JsonWebSigningAlgorithm};

// deserialization

// <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11>:
// > [...] Producers MUST NOT include Header Parameter names
// > defined by this specification or JWA for use with JWS [...]
// This list contains headers defined in JWS and JWA
const DISALLOWED_CRITICAL_HEADERS_JWS: &[&str] = &[
    // JWS section 4.1
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
    // JWA section 4.1
    "epk", "apu", "apv", "iv", "tag", "p2s",
    "p2c",
    // JWE section 4.1 omitted because this is the JWS implementation
];

// <https://datatracker.ietf.org/doc/html/rfc7516/#section-4.1.13> refers to:
// <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11>:
// > [...] Producers MUST NOT include Header Parameter names
// > defined by this specification or JWA for use with JWS [...]
// This list contains headers defined in JWE and JWA
const DISALLOWED_CRITICAL_HEADERS_JWE: &[&str] = &[
    // JWE section 4.1
    "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
    "crit", // JWA section 4.1
    "epk", "apu", "apv", "iv", "tag", "p2s",
    "p2c",
    // JWS section 4.1 omitted because this is the JWE implementation
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct HeaderReprOwned<T, A> {
    // Shared parameters between JWS and JWE
    // `alg` parameter defined in section 4.1.1 in both JWE and JWS
    // alg parameter moved to JwsRepr and JweRepr
    //#[serde(rename = "alg")]
    // pub algorithm: JsonWebAlgorithm,
    // FIXME: use Url type instead
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jku")]
    pub jwk_set_url: Option<String>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jwk")]
    pub json_web_key: Option<JsonWebKey>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "kid")]
    pub key_id: Option<String>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5u")]
    pub x509_url: Option<String>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    #[serde(skip_serializing_if = "Vec::is_empty", default, rename = "x5u")]
    pub x509_certificate_chain: Vec<Base64DerCertificate>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha1",
        deserialize_with = "serde_impl::deserialize_ga_sha1",
        rename = "x5t",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_certificate_sha1_thumbprint: Option<[u8; 20]>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha256",
        deserialize_with = "serde_impl::deserialize_ga_sha256",
        rename = "x5t#S256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_certificate_sha256_thumbprint: Option<[u8; 32]>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        default
    )]
    pub typ: Option<MediaTypeBuf>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        rename = "cty",
        default
    )]
    pub content_type: Option<MediaTypeBuf>,
    /// Additional parameters defined by the generic parameter `A`
    #[serde(flatten)]
    pub additional: A,
    /// Additional parameters which are only present in a specific type of
    /// header ([`Protected`] and [`Unprotected`])
    #[serde(flatten)]
    pub header_type: T,
}

#[derive(Debug, Deserialize)]
struct ProtectedReprOwned {
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    crit: HashSet<String>,
}
#[derive(Debug, Deserialize)]
struct UnprotectedReprOwned {}
#[derive(Debug, Deserialize)]
struct JwsReprOwned<A> {
    alg: JsonWebSigningAlgorithm,
    // only include this header if it is explictly set
    #[serde(skip_serializing_if = "Option::is_none")]
    b64: Option<bool>,
    #[serde(flatten)]
    additional: A,
}
#[derive(Debug, Deserialize)]
struct JweReprOwned<A> {
    alg: JsonWebEncryptionAlgorithm,
    // content encryption algorithm
    enc: JsonWebContentEncryptionAlgorithm,
    #[serde(flatten)]
    additional: A,
}

impl<'de, A> Deserialize<'de> for JwsHeader<Protected, A>
where
    A: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_protected_header(deserializer, DISALLOWED_CRITICAL_HEADERS_JWS)?;
        let repr: HeaderReprOwned<ProtectedReprOwned, JwsReprOwned<A>> =
            HeaderReprOwned::deserialize(value).map_err(D::Error::custom)?;
        let repr: HeaderReprOwned<Protected, Jws<A>> = HeaderReprOwned {
            additional: Jws {
                algorithm: repr.additional.alg,
                payload_base64_url_encoded: repr.additional.b64,
                additional: repr.additional.additional,
            },
            content_type: repr.content_type,
            header_type: Protected {
                critical_headers: repr.header_type.crit,
            },
            json_web_key: repr.json_web_key,
            jwk_set_url: repr.jwk_set_url,
            key_id: repr.key_id,
            typ: repr.typ,
            x509_certificate_chain: repr.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: repr.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: repr.x509_certificate_sha256_thumbprint,
            x509_url: repr.x509_url,
        };
        Ok(JwsHeader { inner: repr })
    }
}
impl<'de, A> Deserialize<'de> for JwsHeader<Unprotected, A>
where
    A: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr: HeaderReprOwned<UnprotectedReprOwned, JwsReprOwned<A>> =
            HeaderReprOwned::deserialize(deserializer)?;
        let repr: HeaderReprOwned<Unprotected, Jws<A>> = HeaderReprOwned {
            additional: Jws {
                algorithm: repr.additional.alg,
                payload_base64_url_encoded: repr.additional.b64,
                additional: repr.additional.additional,
            },
            content_type: repr.content_type,
            header_type: Unprotected {},
            json_web_key: repr.json_web_key,
            jwk_set_url: repr.jwk_set_url,
            key_id: repr.key_id,
            typ: repr.typ,
            x509_certificate_chain: repr.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: repr.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: repr.x509_certificate_sha256_thumbprint,
            x509_url: repr.x509_url,
        };
        Ok(JwsHeader { inner: repr })
    }
}
impl<'de, A> Deserialize<'de> for JweHeader<Protected, A>
where
    A: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_protected_header(deserializer, DISALLOWED_CRITICAL_HEADERS_JWE)?;
        let repr: HeaderReprOwned<ProtectedReprOwned, JweReprOwned<A>> =
            HeaderReprOwned::deserialize(value).map_err(D::Error::custom)?;
        let repr: HeaderReprOwned<Protected, Jwe<A>> = HeaderReprOwned {
            additional: Jwe {
                algorithm: repr.additional.alg,
                content_encryption_algorithm: repr.additional.enc,
                additional: repr.additional.additional,
            },
            content_type: repr.content_type,
            header_type: Protected {
                critical_headers: repr.header_type.crit,
            },
            json_web_key: repr.json_web_key,
            jwk_set_url: repr.jwk_set_url,
            key_id: repr.key_id,
            typ: repr.typ,
            x509_certificate_chain: repr.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: repr.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: repr.x509_certificate_sha256_thumbprint,
            x509_url: repr.x509_url,
        };
        Ok(JweHeader { inner: repr })
    }
}
impl<'de, A> Deserialize<'de> for JweHeader<Unprotected, A>
where
    A: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr: HeaderReprOwned<UnprotectedReprOwned, JweReprOwned<A>> =
            HeaderReprOwned::deserialize(deserializer)?;
        let repr: HeaderReprOwned<Unprotected, Jwe<A>> = HeaderReprOwned {
            additional: Jwe {
                algorithm: repr.additional.alg,
                content_encryption_algorithm: repr.additional.enc,
                additional: repr.additional.additional,
            },
            content_type: repr.content_type,
            header_type: Unprotected {},
            json_web_key: repr.json_web_key,
            jwk_set_url: repr.jwk_set_url,
            key_id: repr.key_id,
            typ: repr.typ,
            x509_certificate_chain: repr.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: repr.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: repr.x509_certificate_sha256_thumbprint,
            x509_url: repr.x509_url,
        };
        Ok(JweHeader { inner: repr })
    }
}

#[inline(always)]
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
#[inline(always)]
fn serialize_mediatype<S>(typ: &Option<MediaTypeBuf>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let typ = match typ.as_ref() {
        Some(typ) => typ,
        // this branch should be unreachable, because Option::None is not serialized
        None => return <Option<&MediaTypeBuf> as Serialize>::serialize(&None, serializer),
    };
    let typ = typ.as_str();

    match typ.split_once('/') {
        // if the typ starts with `application`, strip it if the part after `application` does not
        // contain any other slashes(`/`)
        Some(("application", right)) if !right.contains('/') => right.serialize(serializer),
        // if it doesn't start with `application/` or it contains other slashes, keep the original
        _ => typ.serialize(serializer),
    }
}

/// A function that verifies that the `crit` header only contains parameters
/// that are actually listed in the header. It does not ensure that headers
/// marked as critical are understood.
#[inline(always)]
fn deserialize_protected_header<'de, D>(
    deserializer: D,
    disallowed_critical_headers: &'static [&'static str],
) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    // we have to inspect all field names, so we have to first deserialize it as an
    // untyped JSON Object (Value::Object)
    let fields = Map::<String, Value>::deserialize(deserializer)?;

    if let Some((_, critical_headers)) = fields.iter().find(|(field, _)| *field == "crit") {
        let criticals: HashSet<&str> = match critical_headers {
            Value::Array(array) => {
                // empty `crit` header is forbidden. if there are no critical headers, it should
                // not be included
                if array.is_empty() {
                    return Err(D::Error::custom("found empty `crit` header"));
                }

                let mut set = HashSet::with_capacity(array.len());
                // duplicates in the `crit` array are not allowed.
                for field in array {
                    if !set.insert(match field {
                        Value::String(field) => field.as_str(),
                        _ => {
                            return Err(D::Error::custom(
                                "`crit` header must be a JSON array of strings but it is not",
                            ))
                        }
                    }) {
                        return Err(D::Error::custom(
                            "found duplicate header parameter name in `crit` header",
                        ));
                    }
                }
                set
            }
            _ => {
                return Err(D::Error::custom(
                    "found `crit` header but it is not a JSON array",
                ))
            }
        };

        let disallowed: HashSet<&'static str> = disallowed_critical_headers
            .iter()
            .map(Deref::deref)
            .collect();
        if !criticals.is_disjoint(&disallowed) {
            return Err(D::Error::custom(
                "found critical headers that are not allowed to be critical.",
            ));
        }

        for critical in &criticals {
            if !fields.contains_key(*critical) {
                return Err(D::Error::custom(
                    "found header name marked as critical which is not part of the header",
                ));
            }
        }

        // if there are more headers that most be marked as critical, consider a const
        // array like with disallowed header parameters
        if fields.contains_key("b64") && !criticals.contains("b64") {
            return Err(D::Error::custom(
                "found `b64` which must be marked as critical but it was not",
            ));
        }
    }

    Ok(fields.into())
}

// serialization

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct HeaderReprRef<'a, T, A> {
    // Shared parameters between JWS and JWE
    // `alg` parameter defined in section 4.1.1 in both JWE and JWS
    // alg parameter moved to JwsRepr and JweRepr
    //#[serde(rename = "alg")]
    // pub algorithm: JsonWebAlgorithm,
    // FIXME: use Url type instead
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jku")]
    pub jwk_set_url: &'a Option<String>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "jwk")]
    pub json_web_key: &'a Option<JsonWebKey>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    #[serde(skip_serializing_if = "Option::is_none", rename = "kid")]
    pub key_id: &'a Option<String>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5u")]
    pub x509_url: &'a Option<String>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    #[serde(skip_serializing_if = "Vec::is_empty", default, rename = "x5u")]
    pub x509_certificate_chain: &'a Vec<Base64DerCertificate>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha1",
        deserialize_with = "serde_impl::deserialize_ga_sha1",
        rename = "x5t",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_certificate_sha1_thumbprint: &'a Option<[u8; 20]>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    #[serde(
        serialize_with = "serde_impl::serialize_ga_sha256",
        deserialize_with = "serde_impl::deserialize_ga_sha256",
        rename = "x5t#S256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_certificate_sha256_thumbprint: &'a Option<[u8; 32]>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        default
    )]
    pub typ: &'a Option<MediaTypeBuf>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_mediatype",
        deserialize_with = "deserialize_mediatype",
        rename = "cty",
        default
    )]
    pub content_type: &'a Option<MediaTypeBuf>,
    /// Additional parameters defined by the generic parameter `A`
    #[serde(flatten)]
    pub additional: &'a A,
    /// Additional parameters which are only present in a specific type of
    /// header ([`Protected`] and [`Unprotected`])
    #[serde(flatten)]
    pub header_type: &'a T,
}

#[derive(Debug, Serialize)]
struct ProtectedReprRef<'a> {
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    crit: &'a HashSet<String>,
}
#[derive(Debug, Serialize)]
struct UnprotectedReprRef {}
#[derive(Debug, Serialize)]
struct JwsReprRef<'a, A> {
    alg: &'a JsonWebSigningAlgorithm,
    // only include this header if it is explictly set
    #[serde(skip_serializing_if = "Option::is_none")]
    b64: &'a Option<bool>,
    #[serde(flatten)]
    additional: &'a A,
}
#[derive(Debug, Serialize)]
struct JweReprRef<'a, A> {
    alg: &'a JsonWebEncryptionAlgorithm,
    // content encryption algorithm
    enc: &'a JsonWebContentEncryptionAlgorithm,
    #[serde(flatten)]
    additional: &'a A,
}

#[inline(always)]
fn ensure_critical_headers<S>(
    value: Value,
    disallowed_critical_headers: &'static [&'static str],
) -> Result<Value, S::Error>
where
    S: Serializer,
{
    let actual_parameters = value.as_object().expect("is always serialized as struct");
    if let Some(crits) = value.pointer("/crit") {
        let crits = crits
            .as_array()
            .expect("`crit` is always serialized as array");
        let disallowed: HashSet<&'static str> = disallowed_critical_headers
            .iter()
            .map(Deref::deref)
            .collect();
        for crit in crits {
            let crit = crit.as_str().expect("`crit` array only contains strings");
            if disallowed.contains(&crit) {
                return Err(S::Error::custom(
                    "found critical header that is not allowed to be critical",
                ));
            }

            // `crit` must only contain parameter names that are in the actual header
            if !actual_parameters.contains_key(crit) {
                return Err(S::Error::custom(
                    "found critical header that does not actually exist as parameter",
                ));
            }
        }
    }
    Ok(value)
}

impl<A> Serialize for JwsHeader<Protected, A>
where
    A: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let i = &self.inner;
        let value = serde_json::to_value(HeaderReprRef {
            additional: &JwsReprRef {
                additional: &i.additional.additional,
                alg: &i.additional.algorithm,
                b64: &i.additional.payload_base64_url_encoded,
            },
            content_type: &i.content_type,
            header_type: &ProtectedReprRef {
                crit: &i.header_type.critical_headers,
            },
            json_web_key: &i.json_web_key,
            jwk_set_url: &i.jwk_set_url,
            key_id: &i.key_id,
            typ: &i.typ,
            x509_certificate_chain: &i.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: &i.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: &i.x509_certificate_sha256_thumbprint,
            x509_url: &i.x509_url,
        })
        .map_err(S::Error::custom)?;

        ensure_critical_headers::<S>(value, DISALLOWED_CRITICAL_HEADERS_JWS)?.serialize(serializer)
    }
}
impl<A> Serialize for JwsHeader<Unprotected, A>
where
    A: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let i = &self.inner;
        let value = serde_json::to_value(HeaderReprRef {
            additional: &JwsReprRef {
                additional: &i.additional.additional,
                alg: &i.additional.algorithm,
                b64: &i.additional.payload_base64_url_encoded,
            },
            content_type: &i.content_type,
            header_type: &UnprotectedReprRef {},
            json_web_key: &i.json_web_key,
            jwk_set_url: &i.jwk_set_url,
            key_id: &i.key_id,
            typ: &i.typ,
            x509_certificate_chain: &i.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: &i.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: &i.x509_certificate_sha256_thumbprint,
            x509_url: &i.x509_url,
        })
        .map_err(S::Error::custom)?;
        ensure_critical_headers::<S>(value, DISALLOWED_CRITICAL_HEADERS_JWE)?.serialize(serializer)
    }
}
impl<A> Serialize for JweHeader<Protected, A>
where
    A: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let i = &self.inner;
        HeaderReprRef {
            additional: &JweReprRef {
                additional: &i.additional.additional,
                enc: &i.additional.content_encryption_algorithm,
                alg: &i.additional.algorithm,
            },
            content_type: &i.content_type,
            header_type: &ProtectedReprRef {
                crit: &i.header_type.critical_headers,
            },
            json_web_key: &i.json_web_key,
            jwk_set_url: &i.jwk_set_url,
            key_id: &i.key_id,
            typ: &i.typ,
            x509_certificate_chain: &i.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: &i.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: &i.x509_certificate_sha256_thumbprint,
            x509_url: &i.x509_url,
        }
        .serialize(serializer)
    }
}
impl<A> Serialize for JweHeader<Unprotected, A>
where
    A: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let i = &self.inner;
        HeaderReprRef {
            additional: &JweReprRef {
                additional: &i.additional.additional,
                alg: &i.additional.algorithm,
                enc: &i.additional.content_encryption_algorithm,
            },
            content_type: &i.content_type,
            header_type: &UnprotectedReprRef {},
            json_web_key: &i.json_web_key,
            jwk_set_url: &i.jwk_set_url,
            key_id: &i.key_id,
            typ: &i.typ,
            x509_certificate_chain: &i.x509_certificate_chain,
            x509_certificate_sha1_thumbprint: &i.x509_certificate_sha1_thumbprint,
            x509_certificate_sha256_thumbprint: &i.x509_certificate_sha256_thumbprint,
            x509_url: &i.x509_url,
        }
        .serialize(serializer)
    }
}
