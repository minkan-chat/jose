use openssl::{
    pkey::{Id, PKey, Private, Public},
    sign::{Signer, Verifier},
};
use secrecy::{ExposeSecret, SecretSlice};

use crate::crypto::{backend::interface::okp, Result};

fn id_from_alg(alg: okp::CurveAlgorithm) -> Result<Id> {
    Ok(match alg {
        okp::CurveAlgorithm::Ed25519 => Id::ED25519,
        #[cfg(not(feature = "crypto-aws-lc"))]
        okp::CurveAlgorithm::Ed448 => Id::ED448,
        #[cfg(feature = "crypto-aws-lc")]
        okp::CurveAlgorithm::Ed448 => {
            return Err(super::BackendError::Unsupported("Ed448".to_string()).into())
        }
    })
}

/// A low level private ED key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    key: PKey<Private>,
    public_key: PKey<Public>,

    raw: SecretSlice<u8>,
    raw_public_key: Vec<u8>,
}

impl okp::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(alg: okp::CurveAlgorithm) -> Result<Self> {
        let key = match alg {
            okp::CurveAlgorithm::Ed25519 => PKey::generate_ed25519()?,
            #[cfg(not(feature = "crypto-aws-lc"))]
            okp::CurveAlgorithm::Ed448 => PKey::generate_ed448()?,
            #[cfg(feature = "crypto-aws-lc")]
            okp::CurveAlgorithm::Ed448 => {
                return Err(super::BackendError::Unsupported("Ed448".to_string()).into())
            }
        };

        let raw_public_key = key.raw_public_key()?;
        let public_key = PKey::public_key_from_raw_bytes(&raw_public_key, id_from_alg(alg)?)?;

        Ok(Self {
            raw: SecretSlice::from(key.raw_private_key()?),
            public_key,
            key,
            raw_public_key,
        })
    }

    fn new(alg: okp::CurveAlgorithm, x: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        let key_type = id_from_alg(alg)?;

        let key = PKey::private_key_from_raw_bytes(d.expose_secret(), key_type)?;
        let public_key = PKey::public_key_from_raw_bytes(&x, key_type)?;

        Ok(Self {
            raw: SecretSlice::from(key.raw_private_key()?),
            raw_public_key: public_key.raw_public_key()?,
            public_key,
            key,
        })
    }

    #[inline]
    fn to_bytes(&self) -> SecretSlice<u8> {
        self.raw.clone()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        Self::PublicKey {
            key: self.public_key.clone(),
            raw: self.raw_public_key.clone(),
        }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        let mut signer = Signer::new_without_digest(&self.key)?;
        let sig = signer.sign_oneshot_to_vec(data)?;

        Ok(sig)
    }
}

/// A low level public ED key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    key: PKey<Public>,
    raw: Vec<u8>,
}

impl okp::PublicKey for PublicKey {
    fn new(alg: okp::CurveAlgorithm, x: Vec<u8>) -> Result<Self> {
        let key_type = id_from_alg(alg)?;
        let key = PKey::public_key_from_raw_bytes(&x, key_type)?;

        Ok(Self {
            raw: key.raw_public_key()?,
            key,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        let mut verifier = Verifier::new_without_digest(&self.key)?;
        let valid = verifier.verify_oneshot(signature, msg)?;

        Ok(valid)
    }
}
