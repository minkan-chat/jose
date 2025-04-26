use alloc::vec::Vec;

use ::rsa::{
    traits::{PrivateKeyParts, PublicKeyParts as _},
    BigUint, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::{
    crypto::{backend::interface::rsa, Result},
    jwa::{self, RsaSigning, RsassaPkcs1V1_5, RsassaPss},
};

/// A low level private RSA key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PrivateKey {
    // WARN: It is important that the `inner` key always contains it's precomupted values.
    // It must be ensured that on each construction of this type, `precomputed` method is called
    inner: RsaPrivateKey,
}

impl rsa::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(bits: usize) -> Result<Self> {
        Ok(Self {
            inner: RsaPrivateKey::new(&mut rand_core::OsRng, bits)?,
        })
    }

    fn sign(&mut self, alg: jwa::RsaSigning, data: &[u8]) -> Result<Self::Signature> {
        let hashed = match alg {
            RsaSigning::Pss(RsassaPss::Ps256) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs256) => {
                sha2::Sha256::digest(data).to_vec()
            }
            RsaSigning::Pss(RsassaPss::Ps384) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs384) => {
                sha2::Sha384::digest(data).to_vec()
            }
            RsaSigning::Pss(RsassaPss::Ps512) | RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs512) => {
                sha2::Sha512::digest(data).to_vec()
            }
        };

        let mut rng = rand_core::OsRng;

        let res = match alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => {
                    let pad = Pss::new::<sha2::Sha256>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPss::Ps384 => {
                    let pad = Pss::new::<sha2::Sha384>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPss::Ps512 => {
                    let pad = Pss::new::<sha2::Sha512>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha256>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPkcs1V1_5::Rs384 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha384>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
                RsassaPkcs1V1_5::Rs512 => {
                    let pad = Pkcs1v15Sign::new::<sha2::Sha512>();
                    self.inner.sign_with_rng(&mut rng, pad, &hashed)
                }
            },
        };

        Ok(res?)
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    fn from_components(
        pri: rsa::PrivateKeyComponents,
        pu: rsa::PublicKeyComponents,
    ) -> Result<Self> {
        let n = BigUint::from_bytes_be(&pu.n);
        let e = BigUint::from_bytes_be(&pu.e);

        let d = pri.d.expose_secret();
        let d = BigUint::from_bytes_be(d);

        let p = BigUint::from_bytes_be(pri.prime.p.expose_secret());
        let q = BigUint::from_bytes_be(pri.prime.q.expose_secret());

        let mut key = RsaPrivateKey::from_components(n, e, d, alloc::vec![p, q])?;
        key.precompute()?;
        Ok(Self { inner: key })
    }

    fn private_components(&self) -> Result<rsa::PrivateKeyComponents> {
        let mut primes = self.inner.primes().iter().map(|b| b.to_bytes_be());

        let p = primes
            .next()
            .map(SecretSlice::from)
            .ok_or(super::BackendError::RsaTwoPrimes)?;
        let q = primes
            .next()
            .map(SecretSlice::from)
            .ok_or(super::BackendError::RsaTwoPrimes)?;

        if primes.next().is_some() {
            return Err(super::BackendError::RsaTwoPrimes.into());
        }

        let opt_uint = |x: Option<&BigUint>| {
            x.map(|x| SecretSlice::from(x.to_bytes_be()))
                .expect("key must be precomputed")
        };

        Ok(rsa::PrivateKeyComponents {
            d: SecretSlice::from(self.inner.d().to_bytes_be()),
            prime: rsa::PrivateKeyPrimeComponents {
                p,
                q,
                dp: opt_uint(self.inner.dp()),
                dq: opt_uint(self.inner.dq()),
                qi: {
                    let qi = Zeroizing::new(self.inner.crt_coefficient());
                    opt_uint(qi.as_ref())
                },
            },
        })
    }

    fn public_components(&self) -> rsa::PublicKeyComponents {
        rsa::PublicKeyComponents {
            n: self.inner.n().to_bytes_be(),
            e: self.inner.e().to_bytes_be(),
        }
    }
}

/// A low level public RSA key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PublicKey {
    inner: RsaPublicKey,
}

impl rsa::PublicKey for PublicKey {
    fn from_components(c: rsa::PublicKeyComponents) -> Result<Self> {
        let n = ::rsa::BigUint::from_bytes_be(&c.n);
        let e = ::rsa::BigUint::from_bytes_be(&c.e);
        let key = ::rsa::RsaPublicKey::new(n, e)?;

        Ok(Self { inner: key })
    }

    fn verify(&mut self, alg: jwa::RsaSigning, msg: &[u8], signature: &[u8]) -> Result<bool> {
        let res = match alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => {
                    let hashed = sha2::Sha256::digest(msg);
                    let pad = Pss::new::<sha2::Sha256>();
                    self.inner.verify(pad, &hashed, signature)
                }
                RsassaPss::Ps384 => {
                    let hashed = sha2::Sha384::digest(msg);
                    let pad = Pss::new::<sha2::Sha384>();
                    self.inner.verify(pad, &hashed, signature)
                }
                RsassaPss::Ps512 => {
                    let hashed = sha2::Sha512::digest(msg);
                    let pad = Pss::new::<sha2::Sha512>();
                    self.inner.verify(pad, &hashed, signature)
                }
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => {
                    let hashed = sha2::Sha256::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha256>();
                    self.inner.verify(pad, &hashed, signature)
                }
                RsassaPkcs1V1_5::Rs384 => {
                    let hashed = sha2::Sha384::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha384>();
                    self.inner.verify(pad, &hashed, signature)
                }
                RsassaPkcs1V1_5::Rs512 => {
                    let hashed = sha2::Sha512::digest(msg);
                    let pad = Pkcs1v15Sign::new::<sha2::Sha512>();
                    self.inner.verify(pad, &hashed, signature)
                }
            },
        };

        Ok(res.is_ok())
    }

    fn components(&self) -> rsa::PublicKeyComponents {
        rsa::PublicKeyComponents {
            n: self.inner.n().to_bytes_be(),
            e: self.inner.e().to_bytes_be(),
        }
    }
}
