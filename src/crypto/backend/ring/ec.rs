use alloc::{boxed::Box, vec::Vec};

use pkcs8::{der::Decode as _, PrivateKeyInfo};
use ring::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, KeyPair as _, UnparsedPublicKey},
};
use sec1::EcPrivateKey;
use secrecy::{ExposeSecret as _, SecretSlice};

use crate::{
    crypto::{backend::interface::ec, ec::coordinate_size, Result},
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

/// Converts a public key to x and y coordinates.
fn make_points(alg: jwa::EcDSA, key: &[u8]) -> (&[u8], &[u8]) {
    let size = coordinate_size(alg);

    // SAFETY:
    // This can never panic, because the coordinates are always of exact length,
    // and are not shortened or compressed.
    let x = &key[1..size + 1];
    let y = &key[size + 1..];

    (x, y)
}

fn algorithms(
    alg: jwa::EcDSA,
) -> Result<(
    &'static signature::EcdsaSigningAlgorithm,
    &'static signature::EcdsaVerificationAlgorithm,
)> {
    Ok(match alg {
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
    })
}

pub(crate) struct PrivateKeyData {
    key: EcdsaKeyPair,
    private_material: SecretSlice<u8>,
    pub_key: UnparsedPublicKey<Vec<u8>>,
}

/// A low level private EC key.
pub(crate) struct PrivateKey {
    alg: &'static signature::EcdsaSigningAlgorithm,
    jwa: jwa::EcDSA,
    data: Box<PrivateKeyData>,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            alg: self.alg,
            jwa: self.jwa,
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
            }),
        }
    }
}

impl ec::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(alg: jwa::EcDSA) -> Result<Self> {
        let (sign_alg, verify_alg) = algorithms(alg)?;

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(sign_alg, &rng)?;
        let key = EcdsaKeyPair::from_pkcs8(sign_alg, pkcs8.as_ref(), &rng)?;
        let pubkey = key.public_key().as_ref();

        let private_key_info = PrivateKeyInfo::from_der(pkcs8.as_ref())?;
        let ec_key = EcPrivateKey::from_der(private_key_info.private_key)?;

        Ok(Self {
            alg: sign_alg,
            jwa: alg,
            data: Box::new(PrivateKeyData {
                private_material: SecretSlice::from(ec_key.private_key.to_vec()),
                pub_key: UnparsedPublicKey::new(verify_alg, pubkey.to_vec()),
                key,
            }),
        })
    }

    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        let (sign_alg, verify_alg) = algorithms(alg)?;

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
            jwa: alg,
            data: Box::new(PrivateKeyData {
                key: keypair,
                private_material: d,
                pub_key: UnparsedPublicKey::new(verify_alg, pubkey),
            }),
        })
    }

    #[inline]
    fn private_material(&self) -> &[u8] {
        self.data.private_material.expose_secret()
    }

    #[inline]
    fn public_point(&self) -> (&[u8], &[u8]) {
        make_points(self.jwa, self.data.pub_key.as_ref())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            inner: self.data.pub_key.clone(),
            jwa: self.jwa,
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
    jwa: jwa::EcDSA,
}

impl ec::PublicKey for PublicKey {
    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        let verify_alg = algorithms(alg)?.1;
        let pubkey = UnparsedPublicKey::new(verify_alg, make_public_key(&x, &y));

        Ok(Self {
            jwa: alg,
            inner: pubkey,
        })
    }

    fn to_point(&self) -> (&[u8], &[u8]) {
        make_points(self.jwa, self.inner.as_ref())
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(self.inner.verify(msg, signature).is_ok())
    }
}
