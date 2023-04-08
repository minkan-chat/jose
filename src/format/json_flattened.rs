use core::fmt;

use alloc::string::ToString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    header::{self, HeaderValue},
    jws::{PayloadKind, SignError},
    Base64UrlString, JoseHeader,
};

use super::{sealed, Format};

/// The flattened json serialization format that is a wrapper around
/// a generic json value and that can be deserialized into
/// any serilizable type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonFlattened {
    pub(crate) payload: Base64UrlString,
    pub(crate) protected: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<Value>,
    pub(crate) signature: Base64UrlString,
}

impl Format for JsonFlattened {}

impl fmt::Display for JsonFlattened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = if f.alternate() {
            serde_json::to_string_pretty(&self).map_err(|_| fmt::Error)?
        } else {
            serde_json::to_string(&self).map_err(|_| fmt::Error)?
        };

        f.write_str(&repr)
    }
}

impl sealed::SealedFormat for JsonFlattened {
    type JwsHeader = JoseHeader<JsonFlattened, header::Jws>;
    type SerializedJwsHeader = (Base64UrlString, Option<Value>);

    fn update_header<S: AsRef<[u8]>, D: digest::Update>(
        header: Self::JwsHeader,
        signer: &dyn crate::jws::Signer<S, Digest = D>,
    ) -> Result<Self::JwsHeader, crate::header::JoseHeaderBuilderError> {
        let builder = header
            .into_builder()
            .algorithm(HeaderValue::Protected(signer.algorithm()))
            .key_identifier(
                signer
                    .key_id()
                    .map(ToString::to_string)
                    .map(HeaderValue::Protected),
            );

        builder.build()
    }

    fn provide_header<D: digest::Update>(
        header: Self::JwsHeader,
        digest: &mut D,
    ) -> Result<Self::SerializedJwsHeader, SignError<core::convert::Infallible>> {
        let (protected, unprotected) = header.into_values().map_err(SignError::InvalidHeader)?;
        let header = serde_json::to_string(&protected).map_err(SignError::SerializeHeader)?;

        let protected = Base64UrlString::encode(header.as_bytes());

        digest.update(protected.as_bytes());

        Ok((protected, unprotected.map(Value::Object)))
    }

    fn finalize(
        (protected, unprotected): Self::SerializedJwsHeader,
        payload: PayloadKind,
        signature: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let PayloadKind::Standard(payload) = payload;

        let signature = Base64UrlString::encode(signature);

        Ok(JsonFlattened {
            payload,
            protected,
            header: match unprotected {
                Some(x) => Some(serde_json::to_value(x)?),
                None => None,
            },
            signature,
        })
    }
}
