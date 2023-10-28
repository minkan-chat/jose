use alloc::vec::Vec;

use digest::Digest;
use rand_core::OsRng;
use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};

use crate::{
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm, RsaSigning, RsassaPkcs1V1_5, RsassaPss},
    jwk::FromKey,
    jws::{InvalidSigningAlgorithmError, Signer, Verifier},
};

/// A [`Signer`] using an [`RsaPrivateKey`](super::RsaPrivateKey) and an RSA
/// algorithm.
#[derive(Debug)]
pub struct RsaSigner {
    key: rsa::RsaPrivateKey,
    alg: RsaSigning,
}

impl FromKey<super::RsaPrivateKey> for RsaSigner {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(value: super::RsaPrivateKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::Rsa(alg)) => {
                Ok(Self { key: value.0, alg })
            }
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

impl Signer<Vec<u8>> for RsaSigner {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let key = &mut self.key;

        let hashed = match self.alg {
            RsaSigning::Pss(RsassaPss::Ps256) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs256) => {
                sha2::Sha256::digest(msg).to_vec()
            }
            RsaSigning::Pss(RsassaPss::Ps384) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs384) => {
                sha2::Sha384::digest(msg).to_vec()
            }
            RsaSigning::Pss(RsassaPss::Ps512) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs512) => {
                sha2::Sha512::digest(msg).to_vec()
            }
        };

        let mut rng = OsRng;

        let res = match self.alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => {
                    let pad = Pss::new::<sha2::Sha256>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPss::Ps384 => {
                    let pad = Pss::new::<sha2::Sha384>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPss::Ps512 => {
                    let pad = Pss::new::<sha2::Sha512>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha256>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPkcs1V1_5::Rs384 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha384>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPkcs1V1_5::Rs512 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha512>();
                    key.sign_with_rng(&mut rng, pad, &hashed)
                }
            },
        };

        res.map_err(|_e| {
            #[cfg(not(feature = "std"))]
            let e = signature::Error::new();
            #[cfg(feature = "std")]
            let e = signature::Error::from_source(_e);
            e
        })
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        JsonWebSigningAlgorithm::Rsa(self.alg)
    }
}

/// A [`Verifier`] using an [`RsaPublicKey`](super::RsaPublicKey) and an RSA
/// algorithm.
#[derive(Debug)]
pub struct RsaVerifier {
    key: RsaPublicKey,
    alg: RsaSigning,
}

impl FromKey<super::RsaPublicKey> for RsaVerifier {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(value: super::RsaPublicKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::Rsa(alg)) => {
                Ok(Self { key: value.0, alg })
            }
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

impl FromKey<super::RsaPrivateKey> for RsaVerifier {
    type Error = InvalidSigningAlgorithmError;

    /// Create a [`Verifier`](crate::jws::Verifier) from the private key by
    /// turning it into the public key and dropping the private parts afterwards
    fn from_key(value: super::RsaPrivateKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        Self::from_key(super::RsaPublicKey(value.0.to_public_key()), alg)
    }
}

impl Verifier for RsaVerifier {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
        let key = &self.key;

        let res = match self.alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => {
                    let hashed = sha2::Sha256::digest(msg);
                    let pad = Pss::new::<sha2::Sha256>();
                    key.verify(pad, &hashed, signature)
                }
                RsassaPss::Ps384 => {
                    let hashed = sha2::Sha384::digest(msg);
                    let pad = Pss::new::<sha2::Sha384>();
                    key.verify(pad, &hashed, signature)
                }
                RsassaPss::Ps512 => {
                    let hashed = sha2::Sha512::digest(msg);
                    let pad = Pss::new::<sha2::Sha512>();
                    key.verify(pad, &hashed, signature)
                }
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => {
                    let hashed = sha2::Sha256::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha256>();
                    key.verify(pad, &hashed, signature)
                }
                RsassaPkcs1V1_5::Rs384 => {
                    let hashed = sha2::Sha384::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha384>();
                    key.verify(pad, &hashed, signature)
                }
                RsassaPkcs1V1_5::Rs512 => {
                    let hashed = sha2::Sha512::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha512>();
                    key.verify(pad, &hashed, signature)
                }
            },
        };

        res.map_err(|_e| {
            #[cfg(not(feature = "std"))]
            let e = signature::Error::new();
            #[cfg(feature = "std")]
            let e = signature::Error::from_source(_e);
            e
        })
    }
}
