//! Rsa key types

mod signer_verifier;

use alloc::{boxed::Box, string::String};
use core::convert::Infallible;

use num_bigint_dig::ModInverse;
use num_traits::One;
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint,
};
use serde::{de::Error as _, ser::Error as _, Deserialize, Serialize};
pub use signer_verifier::{RsaSigner, RsaVerifier};

use super::IntoJsonWebKey;
use crate::{
    base64_url::Base64UrlBytes,
    jwa::{self, RsaSigning},
};

/// A public Rsa key used for signature verification and/or encryption
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey(rsa::RsaPublicKey);

impl From<RsaPublicKey> for super::JsonWebKeyType {
    fn from(x: RsaPublicKey) -> Self {
        super::JsonWebKeyType::Asymmetric(Box::new(super::AsymmetricJsonWebKey::Public(
            super::Public::Rsa(x),
        )))
    }
}

impl crate::sealed::Sealed for RsaPublicKey {}
impl IntoJsonWebKey for RsaPublicKey {
    type Algorithm = RsaSigning;
    type Error = Infallible;

    fn into_jwk(
        self,
        alg: impl Into<Option<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let alg = alg
            .into()
            .map(|rsa| jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(rsa)));

        let key = super::JsonWebKeyType::Asymmetric(Box::new(super::AsymmetricJsonWebKey::Public(
            super::Public::Rsa(self),
        )));

        let mut jwk = crate::JsonWebKey::new(key);
        jwk.algorithm = alg;
        Ok(jwk)
    }
}

impl Serialize for RsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Repr {
            kty: &'static str,

            n: Base64UrlBytes,
            e: Base64UrlBytes,
        }

        Repr {
            kty: "RSA",
            n: Base64UrlBytes(self.0.n().to_bytes_be()),
            e: Base64UrlBytes(self.0.e().to_bytes_be()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RsaPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            kty: String,

            n: Base64UrlBytes,
            e: Base64UrlBytes,
        }

        let repr = Repr::deserialize(deserializer)?;

        if &*repr.kty != "RSA" {
            return Err(D::Error::custom("`kty` field is required to be `RSA`"));
        }

        let n = BigUint::from_bytes_be(&repr.n.0);
        let e = BigUint::from_bytes_be(&repr.e.0);

        let key = rsa::RsaPublicKey::new(n, e)
            .map_err(|e| D::Error::custom(alloc::format!("invalid RSA public key: {}", e)))?;
        Ok(Self(key))
    }
}

/// A private Rsa key used to create signatures and/or to decrypt
// INTERNAL NOTE: the inner RsaPrivateKey **MUST** contain exactly two prime factors (p, q)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPrivateKey(rsa::RsaPrivateKey);

impl From<RsaPrivateKey> for super::JsonWebKeyType {
    fn from(x: RsaPrivateKey) -> Self {
        super::JsonWebKeyType::Asymmetric(Box::new(super::AsymmetricJsonWebKey::Private(
            super::Private::Rsa(Box::new(x)),
        )))
    }
}

impl RsaPrivateKey {
    /// Generate a new RSA key pair of the given bit size.
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if the key generation fails.
    pub fn generate(
        mut rng: impl rand_core::CryptoRng + rand_core::RngCore,
        bit_size: usize,
    ) -> rsa::errors::Result<Self> {
        rsa::RsaPrivateKey::new(&mut rng, bit_size).map(Self)
    }

    /// Get the public key corresponding to this private key.
    pub fn to_public_key(&self) -> RsaPublicKey {
        RsaPublicKey(self.0.to_public_key())
    }
}

impl crate::sealed::Sealed for RsaPrivateKey {}
impl IntoJsonWebKey for RsaPrivateKey {
    type Algorithm = RsaSigning;
    type Error = Infallible;

    fn into_jwk(
        self,
        alg: impl Into<Option<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let alg = alg
            .into()
            .map(|rsa| jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(rsa)));

        let key = super::JsonWebKeyType::Asymmetric(Box::new(
            super::AsymmetricJsonWebKey::Private(super::Private::Rsa(Box::new(self))),
        ));

        let mut jwk = crate::JsonWebKey::new(key);
        jwk.algorithm = alg;
        Ok(jwk)
    }
}

impl Serialize for RsaPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Repr {
            kty: &'static str,

            n: Base64UrlBytes,
            e: Base64UrlBytes,

            d: Base64UrlBytes,
            p: Base64UrlBytes,
            q: Base64UrlBytes,
            dp: Base64UrlBytes,
            dq: Base64UrlBytes,
            qi: Base64UrlBytes,
        }

        let d = self.0.d();
        let [p, q]: &[_; 2] = self
            .0
            .primes()
            .try_into()
            .map_err(|_| S::Error::custom("`RsaPrivateKey` must contain exactly two primes"))?;

        let dp = d % (p - BigUint::one());
        let dq = d % (q - BigUint::one());
        let qi = q
            .mod_inverse(p)
            .ok_or_else(|| S::Error::custom("invalid prime factor pair for RsaPrivateKey"))?;

        let dp = Base64UrlBytes(dp.to_bytes_be());
        let dq = Base64UrlBytes(dq.to_bytes_be());
        // FIXME: is it correct to ignore the `Sign`?
        let qi = Base64UrlBytes(qi.to_bytes_be().1);

        let d = Base64UrlBytes(d.to_bytes_be());
        let n = Base64UrlBytes(self.0.n().to_bytes_be());
        let e = Base64UrlBytes(self.0.e().to_bytes_be());

        let p = Base64UrlBytes(p.to_bytes_be());
        let q = Base64UrlBytes(q.to_bytes_be());

        let repr = Repr {
            kty: "RSA",
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qi,
        };

        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RsaPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            kty: String,

            n: Base64UrlBytes,
            e: Base64UrlBytes,
            d: Base64UrlBytes,

            p: Option<Base64UrlBytes>,
            q: Option<Base64UrlBytes>,
            dp: Option<Base64UrlBytes>,
            dq: Option<Base64UrlBytes>,
            qi: Option<Base64UrlBytes>,

            oth: Option<serde_json::Value>,
        }

        let repr = Repr::deserialize(deserializer)?;

        if &*repr.kty != "RSA" {
            return Err(D::Error::custom("`kty` field is required to be `RSA`"));
        }

        let any_prime_present = repr.p.is_some()
            | repr.q.is_some()
            | repr.dp.is_some()
            | repr.dq.is_some()
            | repr.qi.is_some();

        let all_primes_present = [
            ("p", repr.p.is_some()),
            ("q", repr.q.is_some()),
            ("dp", repr.dp.is_some()),
            ("dq", repr.dq.is_some()),
            ("qi", repr.qi.is_some()),
        ];

        if any_prime_present {
            if let Some((field, _)) = all_primes_present.into_iter().find(|(_, x)| !x) {
                return Err(D::Error::custom(alloc::format!(
                    "expected `{}` to be present because all prime fields must be set if one of \
                     them is set",
                    field
                )));
            }
        } else {
            // FIXME: can we support RSA keys without any primes?
            return Err(D::Error::custom(
                "RSA private keys without any primes are not supported",
            ));
        }

        if repr.oth.is_some() {
            // FIXME: Support additional primes
            return Err(D::Error::custom(
                "RSA private keys with `oth` field set are not supported",
            ));
        }

        let n = BigUint::from_bytes_be(&repr.n.0);
        let e = BigUint::from_bytes_be(&repr.e.0);
        let d = BigUint::from_bytes_be(&repr.d.0);
        let p = BigUint::from_bytes_be(
            &repr
                .p
                .expect("we checked before that all primes must be present")
                .0,
        );

        let q = BigUint::from_bytes_be(
            &repr
                .q
                .expect("we checked before that all primes must be present")
                .0,
        );

        let key = rsa::RsaPrivateKey::from_components(n, e, d, alloc::vec![p, q])
            .map_err(D::Error::custom)?;
        Ok(Self(key))
    }
}
