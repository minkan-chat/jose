use alloc::vec::Vec;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use signature::Signer as _;

use crate::crypto::{backend::interface::okp, Result};

#[derive(Clone)]
enum ErasedPrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
}

#[derive(Clone)]
enum ErasedPublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

#[derive(Clone)]
pub(crate) enum ErasedSignature {
    Ed25519([u8; ed25519_dalek::Signature::BYTE_SIZE]),
}

impl From<ErasedSignature> for Vec<u8> {
    fn from(value: ErasedSignature) -> Self {
        match value {
            ErasedSignature::Ed25519(sig) => sig.to_vec(),
        }
    }
}

impl AsRef<[u8]> for ErasedSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            ErasedSignature::Ed25519(ref sig) => sig,
        }
    }
}

/// A low level public ED key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PublicKey {
    inner: ErasedPublicKey,
}

impl okp::PublicKey for PublicKey {
    fn new(alg: okp::CurveAlgorithm, x: Vec<u8>) -> Result<Self> {
        let key = match alg {
            okp::CurveAlgorithm::Ed25519 => {
                let len = x.len();
                let x: [u8; PUBLIC_KEY_LENGTH] =
                    x.try_into()
                        .map_err(|_| super::BackendError::InvalidEcPoint {
                            expected: PUBLIC_KEY_LENGTH,
                            actual: len,
                        })?;
                ErasedPublicKey::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&x)
                        .map_err(super::BackendError::Ed25519)?,
                )
            }
            okp::CurveAlgorithm::Ed448 => {
                return Err(super::BackendError::CurveNotSupported("Ed448").into())
            }
        };

        Ok(Self { inner: key })
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self.inner {
            ErasedPublicKey::Ed25519(ref key) => key.to_bytes().to_vec(),
        }
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        match self.inner {
            ErasedPublicKey::Ed25519(ref key) => {
                // FIXME: this needs interop testing in case this is handled differently by
                // other implementations
                // See <https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html#on-the-multiple-sources-of-malleability-in-ed25519-signatures>

                let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
                    return Ok(false);
                };

                Ok(key.verify_strict(msg, &sig).is_ok())
            }
        }
    }
}

/// A low level public ED key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PrivateKey {
    inner: ErasedPrivateKey,
}

impl okp::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = ErasedSignature;

    fn generate(alg: okp::CurveAlgorithm) -> Result<Self> {
        let key = match alg {
            okp::CurveAlgorithm::Ed25519 => {
                let mut rng = OsRng;
                ErasedPrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng))
            }
            okp::CurveAlgorithm::Ed448 => {
                return Err(super::BackendError::CurveNotSupported("Ed448").into())
            }
        };

        Ok(Self { inner: key })
    }

    fn new(alg: okp::CurveAlgorithm, _x: Vec<u8>, d: Vec<u8>) -> Result<Self> {
        let key = match alg {
            okp::CurveAlgorithm::Ed25519 => {
                let len = d.len();
                let d: [u8; SECRET_KEY_LENGTH] =
                    d.try_into()
                        .map_err(|_| super::BackendError::InvalidEcPoint {
                            expected: SECRET_KEY_LENGTH,
                            actual: len,
                        })?;
                ErasedPrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&d))
            }
            okp::CurveAlgorithm::Ed448 => {
                return Err(super::BackendError::CurveNotSupported("Ed448").into())
            }
        };

        Ok(Self { inner: key })
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self.inner {
            ErasedPrivateKey::Ed25519(ref key) => key.to_bytes().to_vec(),
        }
    }

    fn to_public_key(&self) -> Self::PublicKey {
        let key = match self.inner {
            ErasedPrivateKey::Ed25519(ref key) => {
                let pubkey = key.verifying_key();
                ErasedPublicKey::Ed25519(pubkey)
            }
        };

        PublicKey { inner: key }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        Ok(match self.inner {
            ErasedPrivateKey::Ed25519(ref key) => {
                let sig = key.try_sign(data).map_err(super::BackendError::Ed25519)?;
                ErasedSignature::Ed25519(sig.to_bytes())
            }
        })
    }
}
