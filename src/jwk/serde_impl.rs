use alloc::vec::Vec;
use core::ops::Deref;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use hashbrown::HashSet;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use super::KeyOperation;

/// Helper function to ensure that a [`HashSet`] is created from a [`Vec`]
/// without duplicates
pub fn deserialize_ensure_set<'de, D>(
    deserializer: D,
) -> Result<Option<HashSet<KeyOperation>>, D::Error>
where
    D: Deserializer<'de>,
{
    match <Option<Vec<KeyOperation>> as Deserialize>::deserialize(deserializer)? {
        Some(val) => {
            let mut set = HashSet::new();
            for o in val {
                // detect duplicates in `key_ops` parameter. according to the rfc,
                // > Duplicate key operation values MUST NOT be present in the array.
                // means: this is a set
                if !set.insert(o) {
                    return Err(<D::Error as Error>::custom(
                        "found duplicate in `key_ops` parameter",
                    ));
                }
            }
            Ok(Some(set))
        }
        None => Ok(None),
    }
}

/// serialize a generic array to base64 urlsafe nopad
pub fn serialize_ga<const N: usize, S>(
    // &Option needed because serde passes an &Option<T> instead of Option<&T>
    v: &Option<[u8; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v = v.as_ref();
    v.map(|v| Base64UrlUnpadded::encode_string(v))
        .serialize(serializer)
}

/// deserialize a generic array from base64 urlsafe nopad
pub fn deserialize_ga<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Option::<&str>::deserialize(deserializer)? {
        Some(val) => {
            let mut buf = [0u8; N];
            Base64UrlUnpadded::decode(val, &mut buf).map_err(<D::Error as Error>::custom)?;
            Some(buf)
        }
        None => None,
    })
}

pub fn serialize_ga_sha1<S>(v: &Option<[u8; 20]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_ga::<20, _>(v, serializer)
}

pub fn serialize_ga_sha256<S>(v: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_ga::<32, _>(v, serializer)
}

pub fn deserialize_ga_sha1<'de, D>(deserializer: D) -> Result<Option<[u8; 20]>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_ga::<_, 20>(deserializer)
}

pub fn deserialize_ga_sha256<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_ga::<_, 32>(deserializer)
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub(crate) struct Base64DerCertificate(pub Vec<u8>);

impl<'de> Deserialize<'de> for Base64DerCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = <&str as Deserialize>::deserialize(deserializer)?;
        Ok(Self(
            base64ct::Base64::decode_vec(val).map_err(<D::Error as Error>::custom)?,
        ))
    }
}

impl Deref for Base64DerCertificate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl Serialize for Base64DerCertificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Base64::encode_string(&self.0).serialize(serializer)
    }
}
