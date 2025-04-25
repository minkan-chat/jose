use ring::hmac::Key as RingKey;

use crate::{
    crypto::{backend::interface::hmac, Result},
    jwa,
};

/// A low level HMAC key.
#[repr(transparent)]
pub(crate) struct Key {
    inner: RingKey,
}

impl hmac::Key for Key {
    type Signature = ring::hmac::Tag;

    fn new(variant: jwa::Hmac, data: &[u8]) -> Result<Self> {
        let key = match variant {
            jwa::Hmac::Hs256 => RingKey::new(ring::hmac::HMAC_SHA256, data),
            jwa::Hmac::Hs384 => RingKey::new(ring::hmac::HMAC_SHA384, data),
            jwa::Hmac::Hs512 => RingKey::new(ring::hmac::HMAC_SHA512, data),
        };

        Ok(Self { inner: key })
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        Ok(ring::hmac::sign(&self.inner, data))
    }
}
