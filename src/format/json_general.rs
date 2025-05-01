use alloc::{string::String, vec, vec::Vec};
use core::{convert::Infallible, fmt, marker::PhantomData};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{sealed, Format, Jwe, Jws};
use crate::{
    header::{self, JoseHeaderBuilder, JoseHeaderBuilderError},
    jws::{PayloadData, SignError, Signer},
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
pub struct JsonGeneral<T> {
    pub(crate) payload: Option<Base64UrlString>,
    pub(crate) signatures: Vec<Signature>,
    pub(crate) _crypto_typ: PhantomData<T>,
}

/// A [`JsonWebSignature`](crate::JsonWebSignature) in [`JsonGeneral`] format
pub type JsonGeneralJws = JsonGeneral<Jws>;
/// A [`JsonWebEncryption`](crate::JsonWebEncryption) in [`JsonGeneral`] format
pub type JsonGeneralJwe = JsonGeneral<Jwe>;

impl<T> fmt::Display for JsonGeneral<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = if f.alternate() {
            serde_json::to_string_pretty(&self).map_err(|_| fmt::Error)?
        } else {
            serde_json::to_string(&self).map_err(|_| fmt::Error)?
        };

        f.write_str(&repr)
    }
}

impl Format for JsonGeneralJws {}

impl sealed::SealedFormatJws<JsonGeneralJws> for JsonGeneralJws {
    type JwsHeader = Vec<JoseHeader<JsonGeneralJws, header::Jws>>;
    // this only a single header, even though JsonGeneralJws supports multiple
    // headers, because this trait implementation is only be used for a single
    // signer.
    type SerializedJwsHeader = (
        Option<Base64UrlString>,
        Option<serde_json::Map<String, Value>>,
    );

    fn update_header<S: AsRef<[u8]>>(header: &mut Self::JwsHeader, signer: &dyn Signer<S>) {
        let Some(first) = header.first_mut() else {
            return;
        };

        first.overwrite_alg_and_key_id(signer.algorithm(), signer.key_id());
    }

    fn serialize_header(
        mut header: Self::JwsHeader,
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
        header: Self::SerializedJwsHeader,
        payload: Option<PayloadData>,
        signature: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let payload = payload.map(|PayloadData::Standard(b64)| b64);

        let signature = Base64UrlString::encode(signature);

        Ok(JsonGeneralJws {
            payload,
            signatures: vec![Signature {
                protected: header.0,
                header: header.1,
                signature,
            }],
            _crypto_typ: PhantomData,
        })
    }

    fn finalize_jws_header_builder(
        value_ref: &mut Result<Self::JwsHeader, JoseHeaderBuilderError>,
        new_builder: JoseHeaderBuilder<JsonGeneralJws, header::Jws>,
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
