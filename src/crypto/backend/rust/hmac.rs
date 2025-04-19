use ::hmac::Hmac;
use digest::{Mac as _, Output};

use crate::{
    crypto::{backend::interface::hmac, Result},
    jwa,
};

/// Rust crypto uses generic arguments to represent the variant.
///
/// We don't to that at this level, so we have to erase the type.
enum ErasedKey {
    Hs256(Hmac<sha2::Sha256>),
    Hs384(Hmac<sha2::Sha384>),
    Hs512(Hmac<sha2::Sha512>),
}

pub enum ErasedSignature {
    Hs256(Output<Hmac<sha2::Sha256>>),
    Hs384(Output<Hmac<sha2::Sha384>>),
    Hs512(Output<Hmac<sha2::Sha512>>),
}

impl AsRef<[u8]> for ErasedSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            ErasedSignature::Hs256(sig) => sig.as_ref(),
            ErasedSignature::Hs384(sig) => sig.as_ref(),
            ErasedSignature::Hs512(sig) => sig.as_ref(),
        }
    }
}

/// A low level HMAC key.
#[repr(transparent)]
#[expect(missing_debug_implementations)]
pub struct Key {
    inner: ErasedKey,
}

impl hmac::Key for Key {
    type Signature = ErasedSignature;

    fn new(variant: jwa::Hmac, data: &[u8]) -> Result<Self> {
        let key = match variant {
            jwa::Hmac::Hs256 => ErasedKey::Hs256(Hmac::<sha2::Sha256>::new_from_slice(data)?),
            jwa::Hmac::Hs384 => ErasedKey::Hs384(Hmac::<sha2::Sha384>::new_from_slice(data)?),
            jwa::Hmac::Hs512 => ErasedKey::Hs512(Hmac::<sha2::Sha512>::new_from_slice(data)?),
        };

        Ok(Self { inner: key })
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        let signature = match &mut self.inner {
            ErasedKey::Hs256(hmac) => {
                hmac.update(data);
                ErasedSignature::Hs256(hmac.finalize_reset().into_bytes())
            }
            ErasedKey::Hs384(hmac) => {
                hmac.update(data);
                ErasedSignature::Hs384(hmac.finalize_reset().into_bytes())
            }
            ErasedKey::Hs512(hmac) => {
                hmac.update(data);
                ErasedSignature::Hs512(hmac.finalize_reset().into_bytes())
            }
        };

        Ok(signature)
    }
}
