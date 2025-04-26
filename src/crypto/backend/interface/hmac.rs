//! The interfaces for HMAC.

use crate::{crypto::Result, jwa};

/// The common operations for an HMAC key.
pub(crate) trait Key: Sized {
    /// The signature type that is produced by this key.
    type Signature: AsRef<[u8]>;

    /// Creates a new key from the given data.
    fn new(variant: jwa::Hmac, key: &[u8]) -> Result<Self>;

    /// Signs the given data using this key.
    ///
    /// This operation **must** be re-usable, meaning this method can be
    /// called multiple times with different data to sign.
    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature>;
}
