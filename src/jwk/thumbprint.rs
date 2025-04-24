use alloc::{collections::BTreeMap, string::String, vec::Vec};

use serde::Serialize;

use crate::sealed::Sealed;

/// This trait is implemented by all key types, and can be used
/// to compute the thumbprint of any private, public or symmetric key.
///
/// If you want to use custom hashing functions, call the
/// [`Self::thumbprint_prehashed`] method and hash the result yourself.
pub trait Thumbprint: Sealed {
    /// Compute the thumbprint JSON string of this key.
    ///
    /// This method does not perform any hashing, it only returns
    /// the constructed JSON string, so that it can be hashed
    /// with some custom hashing algorithm that is not supported
    /// natively by this crate.
    ///
    /// For common hashing methods have a look at these methods:
    ///
    /// - SHA256 - [`thumbprint_sha256`](Self::thumbprint_sha256)
    /// - SHA384 - [`thumbprint_sha384`](Self::thumbprint_sha384)
    /// - SHA512 - [`thumbprint_sha512`](Self::thumbprint_sha512)
    ///
    /// # Errors
    ///
    /// This method can fail if the underlying key fails to be serialized.
    fn thumbprint_prehashed(&self) -> String;

    /// Computes the SHA256-hashed thumbprint of this key.
    ///
    /// # Errors
    ///
    /// This method can fail if the underlying key fails to be serialized.
    fn thumbprint_sha256(&self) -> Vec<u8> {
        let msg = self.thumbprint_prehashed();
        crate::crypto::sha256(msg.as_bytes())
    }

    /// Computes the SHA384-hashed thumbprint of this key.
    ///
    /// # Errors
    ///
    /// This method can fail if the underlying key fails to be serialized.
    fn thumbprint_sha384(&self) -> Vec<u8> {
        let msg = self.thumbprint_prehashed();
        crate::crypto::sha384(msg.as_bytes())
    }

    /// Computes the SHA512-hashed thumbprint of this key.
    ///
    /// # Errors
    ///
    /// This method can fail if the underlying key fails to be serialized.
    fn thumbprint_sha512(&self) -> Vec<u8> {
        let msg = self.thumbprint_prehashed();
        crate::crypto::sha512(msg.as_bytes())
    }
}

pub(crate) fn serialize_key_thumbprint<T: Serialize>(key: &T) -> String {
    let obj = serde_json::to_value(key).expect("serialization of OctetSequence can not fail");

    let map = match obj {
        serde_json::Value::Object(map) => BTreeMap::from_iter(map),
        _ => unreachable!("all keytypes must serialize to structs"),
    };

    serde_json::to_string(&map).expect("BTreeMap serialization can not fail")
}
