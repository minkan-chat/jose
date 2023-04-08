use core::{fmt, str::FromStr};

use alloc::string::ToString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    header::{self, HeaderValue},
    jws::{PayloadKind, SignError},
    Base64UrlString, JoseHeader,
};

use super::{sealed, Compact, Format};

/// The flattened json serialization format that is a wrapper around
/// a generic json value and that can be deserialized into
/// any serilizable type.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct JsonFlattened {
    pub(crate) value: Value,
}

impl Format for JsonFlattened {}
impl sealed::SealedFormat for JsonFlattened {
    type JwsHeader = JoseHeader<Compact, header::Jws>;
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
        let mut x = Value::Object(serde_json::Map::default());

        let PayloadKind::Standard(payload) = payload;

        x["payload"] = Value::String(payload.into_inner());
        x["protected"] = Value::String(protected.to_string());

        if let Some(unprotected) = unprotected {
            x["header"] = unprotected;
        }

        let signature = Base64UrlString::encode(signature).into_inner();
        x["signature"] = Value::String(signature);

        Ok(JsonFlattened { value: x })
    }
}

impl JsonFlattened {
    /// Turns this Json wrapper into it's generic underlying Value.
    pub fn into_inner(self) -> Value {
        self.value
    }
}

impl FromStr for JsonFlattened {
    type Err = serde_json::Error;

    /// The from_str implementation will parse the supplied
    /// string as JSON.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = serde_json::from_str::<Value>(s)?;
        Ok(Self { value })
    }
}

impl fmt::Display for JsonFlattened {
    /// The display implementation will format this value
    /// as compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}
