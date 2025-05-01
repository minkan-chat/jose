use alloc::vec::Vec;
use core::fmt::Debug;

use super::{
    encrypt::{EncryptedKey, EncryptionKey},
    JsonWebEncryption,
};
use crate::{
    crypto::Error, format::sealed::SealedFormatJwe, header, jwa::JsonWebEncryptionAlgorithm,
    JoseHeader,
};

pub trait Decryptor {
    fn decrypt(
        &mut self,
        encrypted_key: EncryptedKey,
        alg: &JsonWebEncryptionAlgorithm,
        payload: &[u8],
    ) -> Result<(Vec<u8>, EncryptionKey), Error>;
}

pub struct Decrypted<T> {
    pub inner: T,
    pub encryption_key: EncryptionKey,
}
