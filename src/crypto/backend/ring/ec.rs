use alloc::{boxed::Box, vec::Vec};

use ring::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, UnparsedPublicKey},
};
use secrecy::{ExposeSecret as _, SecretSlice};

use crate::{
    crypto::{backend::interface::ec, Result},
    jwa::{self, EcDSA},
};

/// Converts x and y coordinates to a sequence that is compatible
/// with the "Octet-String-to-Elliptic-Curve-Point Conversion" algorithm
/// defined in Section 2.3.4 of https://www.secg.org/sec1-v2.pdf
fn make_public_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut pubkey = Vec::with_capacity(x.len() + y.len() + 1);
    pubkey.push(0x04); // uncompressed point
    pubkey.extend_from_slice(x);
    pubkey.extend_from_slice(y);
    pubkey
}

pub(crate) struct PrivateKeyData {
    key: EcdsaKeyPair,
    private_material: SecretSlice<u8>,

    pub_key: UnparsedPublicKey<Vec<u8>>,
    x: Vec<u8>,
    y: Vec<u8>,
}

/// A low level private EC key.
pub(crate) struct PrivateKey {
    alg: &'static signature::EcdsaSigningAlgorithm,
    data: Box<PrivateKeyData>,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            alg: self.alg,
            data: Box::new(PrivateKeyData {
                key: EcdsaKeyPair::from_private_key_and_public_key(
                    self.alg,
                    self.data.private_material.expose_secret(),
                    self.data.pub_key.as_ref(),
                    &SystemRandom::new(),
                )
                .expect("this method was already successful with the exact same data"),
                private_material: self.data.private_material.clone(),
                pub_key: self.data.pub_key.clone(),
                x: self.data.x.clone(),
                y: self.data.y.clone(),
            }),
        }
    }
}

impl ec::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(_alg: jwa::EcDSA) -> Result<Self> {
        Err(super::BackendError::Unsupported("EcDSA key generation").into())
    }

    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        let (sign_alg, verify_alg) = match alg {
            EcDSA::Es256 => (
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &signature::ECDSA_P256_SHA256_FIXED,
            ),
            EcDSA::Es384 => (
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                &signature::ECDSA_P384_SHA384_FIXED,
            ),
            EcDSA::Es512 => return Err(super::BackendError::UnsupportedCurve("P-521").into()),
            EcDSA::Es256K => return Err(super::BackendError::UnsupportedCurve("secp256k1").into()),
        };

        let rng = SystemRandom::new();
        let pubkey = make_public_key(&x, &y);

        let keypair = EcdsaKeyPair::from_private_key_and_public_key(
            sign_alg,
            d.expose_secret(),
            &pubkey,
            &rng,
        )?;

        Ok(Self {
            alg: sign_alg,
            data: Box::new(PrivateKeyData {
                key: keypair,
                private_material: d,
                pub_key: UnparsedPublicKey::new(verify_alg, pubkey),
                x,
                y,
            }),
        })
    }

    fn private_material(&self) -> SecretSlice<u8> {
        self.data.private_material.clone()
    }

    #[inline]
    fn public_point(&self) -> (Vec<u8>, Vec<u8>) {
        (self.data.x.clone(), self.data.y.clone())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            inner: self.data.pub_key.clone(),
            x: self.data.x.clone(),
            y: self.data.y.clone(),
        }
    }

    fn sign(&mut self, data: &[u8], deterministic: bool) -> Result<Self::Signature> {
        if deterministic {
            return Err(super::BackendError::Unsupported("deterministic EcDSA signing").into());
        }

        let sig = self.data.key.sign(&SystemRandom::new(), data)?;
        Ok(sig.as_ref().to_vec())
    }
}

/// A low level public EC key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    inner: UnparsedPublicKey<Vec<u8>>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl ec::PublicKey for PublicKey {
    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        let verify_alg = match alg {
            EcDSA::Es256 => &signature::ECDSA_P256_SHA256_FIXED,
            EcDSA::Es384 => &signature::ECDSA_P384_SHA384_FIXED,
            EcDSA::Es512 => return Err(super::BackendError::UnsupportedCurve("P-521").into()),
            EcDSA::Es256K => return Err(super::BackendError::UnsupportedCurve("secp256k1").into()),
        };

        let pubkey = UnparsedPublicKey::new(verify_alg, make_public_key(&x, &y));
        Ok(Self {
            inner: pubkey,
            x,
            y,
        })
    }

    fn to_point(&self) -> (Vec<u8>, Vec<u8>) {
        (self.x.clone(), self.y.clone())
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(self.inner.verify(msg, signature).is_ok())
    }
}
