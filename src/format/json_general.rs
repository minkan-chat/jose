use alloc::{string::String, vec, vec::Vec};
use core::{convert::Infallible, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{sealed, Format};
use crate::{
    header::{self, JoseHeaderBuilder, JoseHeaderBuilderError},
    jws::{PayloadKind, SignError, Signer},
    Base64UrlString, JoseHeader,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Signature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) protected: Option<Base64UrlString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<serde_json::Map<String, Value>>,
    pub(crate) signature: Base64UrlString,
}

/// The JSON General Serialization format as specified in [Section 7.2.1] in the
/// JWS RFC.
///
/// [Section 7.2.1]: https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonGeneral {
    pub(crate) payload: Base64UrlString,
    pub(crate) signatures: Vec<Signature>,
}

impl fmt::Display for JsonGeneral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = if f.alternate() {
            serde_json::to_string_pretty(&self).map_err(|_| fmt::Error)?
        } else {
            serde_json::to_string(&self).map_err(|_| fmt::Error)?
        };

        f.write_str(&repr)
    }
}

impl Format for JsonGeneral {}

impl sealed::SealedFormat<JsonGeneral> for JsonGeneral {
    type JwsHeader = Vec<JoseHeader<JsonGeneral, header::Jws>>;
    // this only a single header, even though JsonGeneral supports multiple headers,
    // because this trait implementation is only be used for a single signer.
    type SerializedJwsHeader = (
        Option<Base64UrlString>,
        Option<serde_json::Map<String, Value>>,
    );

    fn update_header<S: AsRef<[u8]>, D: digest::Update>(
        header: &mut Self::JwsHeader,
        signer: &dyn Signer<S, Digest = D>,
    ) {
        let Some(first) = header.first_mut() else {
            return
        };

        first.overwrite_alg_and_key_id(signer.algorithm(), signer.key_id());
    }

    fn provide_header<D: digest::Update>(
        mut header: Self::JwsHeader,
        digest: &mut D,
    ) -> Result<Self::SerializedJwsHeader, SignError<Infallible>> {
        let len = header.len();

        let Some(header) = header.pop().filter(|_| len == 1) else {
            return Err(SignError::HeaderCountMismatch);
        };

        let (protected, unprotected) = header.into_values().map_err(SignError::InvalidHeader)?;

        let protected = match protected {
            Some(hdr) => {
                let json = serde_json::to_string(&hdr).map_err(SignError::SerializeHeader)?;

                let encoded = Base64UrlString::encode(json);
                digest.update(encoded.as_bytes());
                Some(encoded)
            }
            None => None,
        };

        Ok((protected, unprotected))
    }

    fn finalize(
        header: Self::SerializedJwsHeader,
        payload: PayloadKind,
        signature: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let PayloadKind::Standard(payload) = payload;

        let signature = Base64UrlString::encode(signature);

        Ok(JsonGeneral {
            payload,
            signatures: vec![Signature {
                protected: header.0,
                header: header.1,
                signature,
            }],
        })
    }

    fn finalize_jws_header_builder(
        value_ref: &mut Result<Self::JwsHeader, JoseHeaderBuilderError>,
        new_builder: JoseHeaderBuilder<JsonGeneral, header::Jws>,
    ) {
        let header = match new_builder.build() {
            Ok(header) => header,
            Err(err) => {
                *value_ref = Err(err);
                return;
            }
        };

        match value_ref {
            Ok(headers) => headers.push(header),
            Err(_) => *value_ref = Ok(vec![header]),
        }
    }
}
