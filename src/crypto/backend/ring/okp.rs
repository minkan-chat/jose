use alloc::vec::Vec;

use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use secrecy::{ExposeSecret, SecretSlice};

use crate::crypto::{backend::interface::okp, Result};

/// A low level public ED key.
pub(crate) struct PrivateKey {
    inner: Ed25519KeyPair,
    d: SecretSlice<u8>,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            inner: Ed25519KeyPair::from_seed_and_public_key(
                self.d.expose_secret(),
                self.inner.public_key().as_ref(),
            )
            .expect("this method was already successful with the exact same data"),
            d: self.d.clone(),
        }
    }
}

impl okp::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(_alg: okp::CurveAlgorithm) -> Result<Self> {
        Err(super::BackendError::Unsupported("Ed25519 key generation").into())
    }

    fn new(alg: okp::CurveAlgorithm, x: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        if alg != okp::CurveAlgorithm::Ed25519 {
            return Err(super::BackendError::UnsupportedCurve("Ed2559").into());
        }

        let key = Ed25519KeyPair::from_seed_and_public_key(d.expose_secret(), &x)?;

        Ok(Self { inner: key, d })
    }

    fn to_bytes(&self) -> SecretSlice<u8> {
        self.d.clone()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            inner: UnparsedPublicKey::new(
                &ring::signature::ED25519,
                self.inner.public_key().as_ref().to_vec(),
            ),
        }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        let sig = self.inner.sign(data);
        Ok(sig.as_ref().to_vec())
    }
}

/// A low level public ED key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    inner: UnparsedPublicKey<Vec<u8>>,
}

impl okp::PublicKey for PublicKey {
    fn new(alg: okp::CurveAlgorithm, x: Vec<u8>) -> Result<Self> {
        if alg != okp::CurveAlgorithm::Ed25519 {
            return Err(super::BackendError::UnsupportedCurve("Ed2559").into());
        }

        let key = UnparsedPublicKey::new(&ring::signature::ED25519, x);
        Ok(Self { inner: key })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(self.inner.verify(msg, signature).is_ok())
    }
}
