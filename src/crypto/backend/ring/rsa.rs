use alloc::{vec, vec::Vec};

use ring::{
    rand::SystemRandom,
    rsa::{KeyPair, KeyPairComponents, PublicKeyComponents, RsaParameters},
    signature::RsaEncoding,
};
use secrecy::ExposeSecret;

use crate::{
    crypto::{backend::interface::rsa, Result},
    jwa::{self, RsaSigning, RsassaPkcs1V1_5, RsassaPss},
};

/// A low level private RSA key.
pub(crate) struct PrivateKey {
    inner: KeyPair,

    // store this data, as ring doesn't provide a way to access it
    private_components: rsa::PrivateKeyComponents,
    public_components: rsa::PublicKeyComponents,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let pri = &self.private_components;
        let pu = &self.public_components;
        let components = KeyPairComponents {
            public_key: PublicKeyComponents { n: &pu.n, e: &pu.e },
            d: pri.d.expose_secret(),
            p: pri.prime.p.expose_secret(),
            q: pri.prime.q.expose_secret(),
            dP: pri.prime.dp.expose_secret(),
            dQ: pri.prime.dq.expose_secret(),
            qInv: pri.prime.qi.expose_secret(),
        };

        Self {
            inner: KeyPair::from_components(&components)
                .expect("this method was already successful with the exact same data"),
            private_components: self.private_components.clone(),
            public_components: self.public_components.clone(),
        }
    }
}

impl rsa::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(_bits: usize) -> Result<Self> {
        Err(super::BackendError::Unsupported("RSA key generation").into())
    }

    fn sign(&mut self, alg: jwa::RsaSigning, data: &[u8]) -> Result<Self::Signature> {
        let padding_alg: &'static dyn RsaEncoding = match alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => &ring::signature::RSA_PSS_SHA256,
                RsassaPss::Ps384 => &ring::signature::RSA_PSS_SHA384,
                RsassaPss::Ps512 => &ring::signature::RSA_PSS_SHA512,
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => &ring::signature::RSA_PKCS1_SHA512,
                RsassaPkcs1V1_5::Rs384 => &ring::signature::RSA_PKCS1_SHA384,
                RsassaPkcs1V1_5::Rs512 => &ring::signature::RSA_PKCS1_SHA512,
            },
        };

        let rng = SystemRandom::new();
        let mut sig = vec![0; self.inner.public().modulus_len()];
        self.inner.sign(padding_alg, &rng, data, &mut sig)?;
        Ok(sig)
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            components: self.public_components.clone(),
        }
    }

    fn from_components(
        pri: rsa::PrivateKeyComponents,
        pu: rsa::PublicKeyComponents,
    ) -> Result<Self> {
        let components = KeyPairComponents {
            public_key: PublicKeyComponents { n: &pu.n, e: &pu.e },
            d: pri.d.expose_secret(),
            p: pri.prime.p.expose_secret(),
            q: pri.prime.q.expose_secret(),
            dP: pri.prime.dp.expose_secret(),
            dQ: pri.prime.dq.expose_secret(),
            qInv: pri.prime.qi.expose_secret(),
        };
        let key = KeyPair::from_components(&components)?;

        Ok(Self {
            inner: key,
            private_components: pri,
            public_components: pu,
        })
    }

    fn private_components(&self) -> Result<rsa::PrivateKeyComponents> {
        Ok(self.private_components.clone())
    }

    fn public_components(&self) -> rsa::PublicKeyComponents {
        self.public_components.clone()
    }
}

/// A low level public RSA key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    components: rsa::PublicKeyComponents,
}

impl rsa::PublicKey for PublicKey {
    fn from_components(c: rsa::PublicKeyComponents) -> Result<Self> {
        Ok(Self { components: c })
    }

    fn verify(&mut self, alg: jwa::RsaSigning, msg: &[u8], signature: &[u8]) -> Result<bool> {
        let params: &'static RsaParameters = match alg {
            RsaSigning::Pss(pss) => match pss {
                RsassaPss::Ps256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
                RsassaPss::Ps384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
                RsassaPss::Ps512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
            },
            RsaSigning::RsPkcs1V1_5(pkcs) => match pkcs {
                RsassaPkcs1V1_5::Rs256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                RsassaPkcs1V1_5::Rs384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
                RsassaPkcs1V1_5::Rs512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            },
        };

        let rsa = PublicKeyComponents {
            n: &self.components.n,
            e: &self.components.e,
        };

        Ok(rsa.verify(params, msg, signature).is_ok())
    }

    fn components(&self) -> rsa::PublicKeyComponents {
        self.components.clone()
    }
}
