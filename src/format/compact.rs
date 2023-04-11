use alloc::{string::ToString, vec::Vec};
use core::{fmt, str::FromStr};

use super::{sealed, Format};
use crate::{
    base64_url::NoBase64UrlString,
    header::{self, HeaderValue},
    jws::{PayloadKind, SignError, Signer},
    Base64UrlString, JoseHeader,
};

/// The compact representation is essentially a list of Base64Url
/// strings that are separated by `.`.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Compact {
    parts: Vec<Base64UrlString>,
}

impl Format for Compact {}
impl sealed::SealedFormat for Compact {
    type JwsHeader = JoseHeader<Compact, header::Jws>;
    type SerializedJwsHeader = Base64UrlString;

    fn update_header<S: AsRef<[u8]>, D: digest::Update>(
        header: &mut Self::JwsHeader,
        signer: &dyn Signer<S, Digest = D>,
    ) {
        let is_protected = matches!(header.algorithm(), HeaderValue::Protected(_));

        let alg = if is_protected {
            HeaderValue::Protected(signer.algorithm())
        } else {
            HeaderValue::Unprotected(signer.algorithm())
        };

        let kid = signer.key_id().map(|s| {
            let kid = s.to_string();
            if is_protected {
                HeaderValue::Protected(kid)
            } else {
                HeaderValue::Unprotected(kid)
            }
        });

        header.set_alg_and_key_id(alg, kid);
    }

    fn provide_header<D: digest::Update>(
        header: Self::JwsHeader,
        digest: &mut D,
    ) -> Result<Self::SerializedJwsHeader, SignError<core::convert::Infallible>> {
        let (protected_header, _) = header.into_values().map_err(SignError::InvalidHeader)?;

        if protected_header
            .as_ref()
            .map(|x| x.is_empty())
            .unwrap_or(true)
        {
            return Err(SignError::EmptyProtectedHeader);
        }

        let header =
            serde_json::to_string(&protected_header).map_err(SignError::SerializeHeader)?;

        let header = Base64UrlString::encode(header.as_bytes());

        digest.update(header.as_bytes());

        Ok(header)
    }

    fn finalize(
        header: Self::SerializedJwsHeader,
        payload: PayloadKind,
        signature: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let mut compact = Compact::with_capacity(3);

        compact.push_base64url(header);

        let PayloadKind::Standard(payload) = payload;

        compact.parts.push(payload);
        compact.push(signature);

        Ok(compact)
    }
}

impl Compact {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Compact {
            parts: Vec::with_capacity(cap),
        }
    }

    pub(crate) fn push_base64url(&mut self, part: Base64UrlString) {
        self.parts.push(part);
    }

    pub(crate) fn push(&mut self, part: impl AsRef<[u8]>) {
        self.parts.push(Base64UrlString::encode(part));
    }

    pub(crate) fn part(&self, idx: usize) -> Option<&Base64UrlString> {
        self.parts.get(idx)
    }

    pub(crate) fn len(&self) -> usize {
        self.parts.len()
    }
}

impl FromStr for Compact {
    type Err = NoBase64UrlString;

    /// Verifies if every part of the string is valid base64url format
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s
            .split('.')
            .map(Base64UrlString::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { parts })
    }
}

impl fmt::Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.parts.len();

        for (idx, part) in self.parts.iter().enumerate() {
            fmt::Display::fmt(&part, f)?;

            if idx != len - 1 {
                f.write_str(".")?;
            }
        }

        Ok(())
    }
}
