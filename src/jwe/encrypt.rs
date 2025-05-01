use alloc::{string::String, vec::Vec};

use crate::{
    base64_url::{Base64UrlBytes, SecretBase64UrlBytes},
    crypto::Error,
    format::sealed::SealedFormatJwe,
    jwa::{JsonWebContentEncryptionAlgorithm, JsonWebEncryptionAlgorithm},
    Base64UrlString, JoseHeader,
};

/// A type that can be used to produce [`Encrypted`].
///
/// # Note
///
/// Internally, an implementing type may perform key wrapping etc based on the
/// provided algorithm.
pub trait Encryptor<T: AsRef<[u8]>> {
    fn encrypt(&mut self, payload: &[u8]) -> Result<(T, EncryptedKey), Error>;
    fn algorithm(&self) -> JsonWebEncryptionAlgorithm;
    fn content_encryption_algorithm(&self) -> JsonWebContentEncryptionAlgorithm;
}

/// Contains the key used to encrypt a
/// [`JsonWebEncryption`](crate::JsonWebEncryption)
///
/// In other protocols, this would be called a encrypted session key
///
/// # Note
///
/// It is possible that there are different [`EncryptedKey`] instances that each
/// contain the same [`EncryptionKey`] for different recipients
#[doc(alias = "EncryptedSessionKey")]
#[derive(Debug)]
pub struct EncryptedKey {
    pub(super) enc: JsonWebContentEncryptionAlgorithm,
    pub(super) material: Base64UrlBytes,
}

/// A symmetric key used to encrypt a payload
#[doc(alias = "SessionKey")]
#[derive(Debug)]
pub struct EncryptionKey {
    enc: JsonWebContentEncryptionAlgorithm,
    material: SecretBase64UrlBytes,
}

/// Some payload encrypted in a format
pub struct Encrypted<F>
where
    F: SealedFormatJwe,
{
    /// Protected and unprotected header
    pub header: F::JweHeader,
    /// Key that is used to encrypt the payload. The key is only used once and
    /// itself encrypted by a longer lived key.
    pub encrypted_key: EncryptedKey,
    // must be non empty or none
    pub iv: Option<Base64UrlBytes>,
    // encrypted payload
    pub ciphertext: Base64UrlBytes,
    pub tag: Option<Base64UrlBytes>,
    // has only a single one for compact and json flattend
}
