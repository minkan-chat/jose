use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use digest::OutputSizeUser;
use generic_array::GenericArray;
use hashbrown::HashSet;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::Sha256;

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
pub fn serialize_ga<T, S>(
    // &Option needed because serde passes an &Option<T> instead of Option<&T>
    v: &Option<GenericArray<u8, T::OutputSize>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: OutputSizeUser,
    S: Serializer,
{
    let v = v.as_ref();
    v.map(|v| Base64UrlUnpadded::encode_string(v))
        .serialize(serializer)
}

/// deserialize a generic array from base64 urlsafe nopad
pub fn deserialize_ga<'de, D, T>(
    deserializer: D,
) -> Result<Option<GenericArray<u8, T::OutputSize>>, D::Error>
where
    D: Deserializer<'de>,
    T: OutputSizeUser,
{
    Ok(match Option::<&str>::deserialize(deserializer)? {
        Some(val) => {
            let mut buf: GenericArray<u8, T::OutputSize> = GenericArray::default();
            Base64UrlUnpadded::decode(val, &mut buf).map_err(<D::Error as Error>::custom)?;
            Some(buf)
        }
        None => None,
    })
}

pub fn serialize_ga_sha1<S>(
    v: &Option<GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_ga::<Sha1, _>(v, serializer)
}

pub fn serialize_ga_sha256<S>(
    v: &Option<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_ga::<Sha256, _>(v, serializer)
}

pub fn deserialize_ga_sha1<'de, D>(
    deserializer: D,
) -> Result<Option<GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_ga::<_, Sha1>(deserializer)
}

pub fn deserialize_ga_sha256<'de, D>(
    deserializer: D,
) -> Result<Option<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_ga::<_, Sha256>(deserializer)
}
