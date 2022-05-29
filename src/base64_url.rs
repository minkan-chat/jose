//! Helpers for base64 urlsafe encoded stuff

use alloc::format;

use base64ct::{Base64UrlUnpadded, Encoding};
use digest::typenum::Unsigned;
use elliptic_curve::{bigint::ArrayEncoding, Curve, FieldBytes};
use generic_array::{ArrayLength, GenericArray};
use serde::{de::Error, Deserialize};

#[derive(Debug)]
pub(crate) struct Base64UrlOctet<N: ArrayLength<u8>>(GenericArray<u8, N>);

impl<'de, N> Deserialize<'de> for Base64UrlOctet<N>
where
    N: ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&str as Deserialize>::deserialize(deserializer)?;

        // let len = s.len();
        // FIXME: this check fails but shouldn't?
        // if len != <N as Unsigned>::to_usize() {
        // return Err(Error::custom(format!(
        // "Expected a base64url encoded string with a length of {}, found a string with
        // a \ length of {}.",
        // len,
        // <N as Unsigned>::to_usize(),
        // )));
        // }
        let mut buf = GenericArray::<u8, N>::default();
        Base64UrlUnpadded::decode(&s, &mut buf).map_err(<D::Error as Error>::custom)?;
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
        D: serde::Deserializer<'de>,
    {
        let field: Base64UrlOctet<<C::UInt as ArrayEncoding>::ByteSize> =
            Base64UrlOctet::deserialize(deserializer)?;
        Ok(Self(field.0))
    }
}
#[cfg(test)]
mod tests {}
