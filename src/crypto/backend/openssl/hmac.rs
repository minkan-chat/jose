use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::{
    crypto::{backend::interface::hmac, Result},
    jwa,
};

/// A low level HMAC key.
pub(crate) struct Key {
    inner: PKey<Private>,
    digest: MessageDigest,
}

impl hmac::Key for Key {
    type Signature = Vec<u8>;

    fn new(variant: jwa::Hmac, data: &[u8]) -> Result<Self> {
        Ok(Self {
            digest: match variant {
                jwa::Hmac::Hs256 => MessageDigest::sha256(),
                jwa::Hmac::Hs384 => MessageDigest::sha384(),
                jwa::Hmac::Hs512 => MessageDigest::sha512(),
            },
            inner: PKey::hmac(data)?,
        })
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        let mut signer = Signer::new(self.digest, &self.inner)?;
        signer.update(data)?;
        let sig = signer.sign_to_vec()?;
        Ok(sig)
    }
}
