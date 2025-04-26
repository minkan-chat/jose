use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

use mediatype::MediaTypeBuf;
use serde::{de::Error, Deserialize, Serialize};
use serde_json::Value;

use super::HeaderValue;
use crate::{jwk::serde_impl::Base64DerCertificate, JsonWebKey, UntypedAdditionalProperties, Uri};

#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct Parameters<T> {
    /// `crit` header MUST always be protected
    pub(crate) critical_headers: Option<BTreeSet<String>>,
    /// `jku` parameter defined in section 4.1.2 of JWS and section 4.1.4 of JWE
    pub(crate) jwk_set_url: Option<HeaderValue<Uri>>,
    /// `jwk` parameter defined in section 4.1.3 of JWS and section 4.1.5 of JWE
    pub(crate) json_web_key: Option<HeaderValue<JsonWebKey<UntypedAdditionalProperties>>>,
    // `kid` parameter defined in section 4.1.4 of JWS and section 4.1.6 of JWE
    pub(crate) key_id: Option<HeaderValue<String>>,
    /// `x5u` parameter defined in section 4.1.5 of JWS and section 4.1.7 of JWE
    // FIXME: use url type instead
    pub(crate) x509_url: Option<HeaderValue<Uri>>,
    /// `x5c` parameter defined in section 4.1.6 of JWS and section 4.1.8 of JWE
    pub(crate) x509_certificate_chain: Option<HeaderValue<Vec<Base64DerCertificate>>>,
    /// `x5t` parameter defined in section 4.1.7 of JWS and section 4.1.9 of JWE
    pub(crate) x509_certificate_sha1_thumbprint: Option<HeaderValue<[u8; 20]>>,
    /// `x5t#S256` parameter defined in section 4.1.8 of JWS and section 4.1.10
    /// of JWE
    pub(crate) x509_certificate_sha256_thumbprint: Option<HeaderValue<[u8; 32]>>,
    /// `typ` parameter defined in section 4.1.9 of JWS and section 4.1.11 of
    /// JWE
    pub(crate) typ: Option<HeaderValue<MediaTypeWithMaybeStrippedApplicationTopLevel>>,
    /// `cty` parameter defined in section 4.1.10 of JWS and section 4.1.12 of
    /// JWE
    pub(crate) content_type: Option<HeaderValue<MediaTypeWithMaybeStrippedApplicationTopLevel>>,
    // additional parameters specific to JWS or JWE (e.g. `enc` in JWE)
    pub(crate) specific: T,
    // an untyped list of other values that are not understood by this implementation
    pub(crate) additional: BTreeMap<String, HeaderValue<Value>>,
}

/// A wrapper type that incorporates the special handling of `application/X`
/// media types in `typ` and `cty` header parameters as defined in [Section
/// 4.1.9 of RFC 7515][1].
///
/// See [#128].
///
/// If the mediatype starts with `application/` and no other `/` is present,
/// implementations should strip the `application/` to save space.
///
/// Since this is a serialization detail, we abstract it away, because the
/// meaning remains the same and this way users can easily use the mediatype
/// crate.
///
/// [#128]: <https://github.com/minkan-chat/jose/issues/128>
/// [1]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9>
#[derive(Debug)]
pub(crate) struct MediaTypeWithMaybeStrippedApplicationTopLevel(pub(crate) MediaTypeBuf);

impl<'de> Deserialize<'de> for MediaTypeWithMaybeStrippedApplicationTopLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: Cow<'_, str> = Cow::deserialize(deserializer)?;
        // if there is no `/` in the media type the RFC dictates to prepend
        // `application/`
        let corrected = if !raw.contains('/') {
            alloc::format!("application/{raw}")
        } else {
            raw.to_string()
        };
        let inner = MediaTypeBuf::from_string(corrected).map_err(D::Error::custom)?;
        Ok(Self(inner))
    }
}

impl Serialize for MediaTypeWithMaybeStrippedApplicationTopLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let correct = self.0.to_string();
        if self.0.ty() == mediatype::names::APPLICATION
            // ensure media type contains exactly one slash (parameters included)
            && correct.chars().filter(|c| *c == '/').count() == 1
        {
            let raw = correct.split_once('/').expect("contains one slash").1;
            // these should be UPPERCASE for interop with legacy implementation according to
            // the JOSE RFCs..
            const SHOULD_BE_UPPERCASE: [&str; 2] = ["jwt", "jose"];
            Ok(
                if SHOULD_BE_UPPERCASE.contains(&raw.to_lowercase().as_str()) {
                    raw.to_uppercase().serialize(serializer)?
                } else {
                    raw.serialize(serializer)?
                },
            )
        } else {
            correct.serialize(serializer)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use mediatype::{
        names::{APPLICATION, JWT},
        MediaType,
    };
    use serde::{Deserialize, Serialize};

    use super::MediaTypeWithMaybeStrippedApplicationTopLevel;

    #[derive(Deserialize, Serialize)]
    struct Dummy {
        typ: MediaTypeWithMaybeStrippedApplicationTopLevel,
    }
    #[test]
    fn jwt_without_application_roundtrip() {
        let payload = r#"{"typ":"JWT"}"#;
        let a: Dummy = serde_json::from_str(payload).expect("valid");
        assert_eq!(a.typ.0, MediaType::new(APPLICATION, JWT));
        let json: String = serde_json::to_string(&a).expect("valid");
        assert_eq!(json, payload);
    }
}
