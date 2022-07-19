//! Helpers for base64 urlsafe encoded stuff

use alloc::{string::String, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use elliptic_curve::{bigint::ArrayEncoding, Curve, FieldBytes};
use generic_array::{ArrayLength, GenericArray};
use serde::{de::Error, Deserialize, Deserializer, Serialize};

#[derive(Debug)]
pub(crate) struct Base64UrlBytes(pub(crate) Vec<u8>);

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(&self.0);
        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;

        let decoded = Base64UrlUnpadded::decode_vec(&encoded)
            .map_err(|_| D::Error::custom("encountered invalid Base64Url string"))?;

        Ok(Self(decoded))
    }
}

#[derive(Debug)]
pub(crate) struct Base64UrlOctet<N: ArrayLength<u8>>(GenericArray<u8, N>);

impl<'de, N> Deserialize<'de> for Base64UrlOctet<N>
where
    N: ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;

        // let len = s.len();
        // FIXME: this check fails but shouldn't?
        // According to the JWA RFC (6.2.1.2):
        // > The length of this octet string MUST
        // > be the full size of a coordinate for the curve specified in the "crv"
        // > parameter.
        // if len != <N as Unsigned>::to_usize() {
        // return Err(Error::custom(format!(
        // "Expected a base64url encoded string with a length of {}, found a string with
        // a \ length of {}.",
        // len,
        // <N as Unsigned>::to_usize(),
        // )));
        // }
        let mut buf = GenericArray::<u8, N>::default();
        Base64UrlUnpadded::decode(&*s, &mut buf).map_err(<D::Error as Error>::custom)?;
        Ok(Self(buf))
    }
}

/// Used for <http://www.secg.org/sec1-v2.pdf> section 2.3.5
pub(crate) struct Base64UrlEncodedField<C>(pub(crate) FieldBytes<C>)
where
    C: Curve;

impl<'de, C> Deserialize<'de> for Base64UrlEncodedField<C>
where
    C: Curve,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let field: Base64UrlOctet<<C::UInt as ArrayEncoding>::ByteSize> =
            Base64UrlOctet::deserialize(deserializer)?;
        Ok(Self(field.0))
    }
}

impl<C> Serialize for Base64UrlEncodedField<C>
where
    C: Curve,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<C> From<FieldBytes<C>> for Base64UrlEncodedField<C>
where
    C: Curve,
{
    fn from(v: FieldBytes<C>) -> Self {
        Self(v)
    }
}

// TODO: test for correct length check and base64url parsing
#[cfg(test)]
mod tests {}
