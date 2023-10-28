use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{sealed, Format};
use crate::{
    header,
    jws::{PayloadKind, SignError},
    Base64UrlString, JoseHeader,
};

/// The flattened json serialization format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonFlattened {
    pub(crate) payload: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) protected: Option<Base64UrlString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<serde_json::Map<String, Value>>,
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

impl sealed::SealedFormat<JsonFlattened> for JsonFlattened {
    type JwsHeader = JoseHeader<JsonFlattened, header::Jws>;
    type SerializedJwsHeader = (
        Option<Base64UrlString>,
        Option<serde_json::Map<String, Value>>,
    );

    fn update_header<S: AsRef<[u8]>>(
        header: &mut Self::JwsHeader,
        signer: &dyn crate::jws::Signer<S>,
    ) {
        header.overwrite_alg_and_key_id(signer.algorithm(), signer.key_id());
    }

    fn serialize_header(
        header: Self::JwsHeader,
    ) -> Result<Self::SerializedJwsHeader, SignError<core::convert::Infallible>> {
        let (protected, unprotected) = header.into_values().map_err(SignError::InvalidHeader)?;

        let protected = match protected {
            Some(hdr) => {
                let json = serde_json::to_string(&hdr).map_err(SignError::SerializeHeader)?;

                let encoded = Base64UrlString::encode(json);
                Some(encoded)
            }
            None => None,
        };

        Ok((protected, unprotected))
    }

    fn message_from_header(hdr: &Self::SerializedJwsHeader) -> Option<&[u8]> {
        hdr.0.as_ref().map(|x| x.as_bytes())
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
            header: unprotected,
            signature,
        })
    }

    fn finalize_jws_header_builder(
        value_ref: &mut Result<Self::JwsHeader, header::JoseHeaderBuilderError>,
        new_builder: header::JoseHeaderBuilder<JsonFlattened, header::Jws>,
    ) {
        *value_ref = new_builder.build();
    }
}
