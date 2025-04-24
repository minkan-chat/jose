use alloc::vec::Vec;

use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
};

use crate::{
    crypto::{backend::interface::rsa, Result},
    jwa,
};

fn digest(alg: jwa::RsaSigning) -> MessageDigest {
    match alg {
        jwa::RsaSigning::Pss(pss) => match pss {
            jwa::RsassaPss::Ps256 => MessageDigest::sha256(),
            jwa::RsassaPss::Ps384 => MessageDigest::sha384(),
            jwa::RsassaPss::Ps512 => MessageDigest::sha512(),
        },
        jwa::RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
            jwa::RsassaPkcs1V1_5::Rs256 => MessageDigest::sha256(),
            jwa::RsassaPkcs1V1_5::Rs384 => MessageDigest::sha384(),
            jwa::RsassaPkcs1V1_5::Rs512 => MessageDigest::sha512(),
        },
    }
}

/// A low level private RSA key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    private_key: PKey<Private>,
    public_key: PKey<Public>,

    private_data: Rsa<Private>,
    public_data: Rsa<Public>,
}

impl rsa::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn from_components(
        pri: rsa::PrivateKeyComponents,
        pu: rsa::PublicKeyComponents,
    ) -> Result<Self> {
        let n = BigNum::from_slice(&pu.n)?;
        let e = BigNum::from_slice(&pu.e)?;
        let d = BigNum::from_slice(&pri.d)?;
        let p = BigNum::from_slice(&pri.prime.p)?;
        let q = BigNum::from_slice(&pri.prime.q)?;
        let dp = BigNum::from_slice(&pri.prime.dp)?;
        let dq = BigNum::from_slice(&pri.prime.dq)?;
        let qi = BigNum::from_slice(&pri.prime.qi)?;

        let private_data = Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?;
        private_data.check_key()?;

        let n = BigNum::from_slice(&pu.n)?;
        let e = BigNum::from_slice(&pu.e)?;
        let public_data = Rsa::from_public_components(n, e)?;

        Ok(Self {
            private_key: PKey::from_rsa(private_data.clone())?,
            public_key: PKey::from_rsa(public_data.clone())?,
            private_data,
            public_data,
        })
    }

    fn sign(&mut self, alg: jwa::RsaSigning, data: &[u8]) -> Result<Self::Signature> {
        let digest = digest(alg);
        let mut signer = Signer::new(digest, &self.private_key)?;

        // FIXME: verify correct setting of parameters
        match alg {
            jwa::RsaSigning::Pss(..) => {
                signer.set_rsa_mgf1_md(digest)?;
                signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            }
            jwa::RsaSigning::RsPkcs1V1_5(..) => {
                signer.set_rsa_padding(Padding::PKCS1)?;
            }
        }

        signer.update(data)?;
        let sig = signer.sign_to_vec()?;
        Ok(sig)
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            key: self.public_key.clone(),
            data: self.public_data.clone(),
        }
    }

    fn private_components(&self) -> Result<rsa::PrivateKeyComponents> {
        let err = || super::BackendError::NoPrimeData;

        let d = self.private_data.d().to_vec();
        let p = self.private_data.p().ok_or_else(err)?.to_vec();
        let q = self.private_data.q().ok_or_else(err)?.to_vec();
        let dp = self.private_data.dmp1().ok_or_else(err)?.to_vec();
        let dq = self.private_data.dmq1().ok_or_else(err)?.to_vec();
        let qi = self.private_data.iqmp().ok_or_else(err)?.to_vec();

        Ok(rsa::PrivateKeyComponents {
            d,
            prime: rsa::PrivateKeyPrimeComponents { p, q, dp, dq, qi },
        })
    }

    fn public_components(&self) -> rsa::PublicKeyComponents {
        let n = self.private_data.n().to_vec();
        let e = self.private_data.e().to_vec();
        rsa::PublicKeyComponents { n, e }
    }
}

/// A low level public RSA key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    key: PKey<Public>,
    data: Rsa<Public>,
}

impl rsa::PublicKey for PublicKey {
    fn from_components(c: rsa::PublicKeyComponents) -> Result<Self> {
        let n = BigNum::from_slice(&c.n)?;
        let e = BigNum::from_slice(&c.e)?;
        let data = Rsa::from_public_components(n, e)?;

        Ok(Self {
            key: PKey::from_rsa(data.clone())?,
            data,
        })
    }

    fn verify(&mut self, alg: jwa::RsaSigning, msg: &[u8], signature: &[u8]) -> Result<bool> {
        let digest = digest(alg);
        let mut verifier = Verifier::new(digest, &self.key)?;

        // FIXME: verify correct setting of parameters
        match alg {
            jwa::RsaSigning::Pss(..) => {
                verifier.set_rsa_mgf1_md(digest)?;
                verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            }
            jwa::RsaSigning::RsPkcs1V1_5(..) => {
                verifier.set_rsa_padding(Padding::PKCS1)?;
            }
        }

        verifier.update(msg)?;
        let valid = verifier.verify(signature)?;
        Ok(valid)
    }

    fn components(&self) -> rsa::PublicKeyComponents {
        rsa::PublicKeyComponents {
            n: self.data.n().to_vec(),
            e: self.data.e().to_vec(),
        }
    }
}
