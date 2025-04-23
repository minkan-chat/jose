//! The primitives for working with [RSA] encryption.
//!
//! [RSA]: https://en.wikipedia.org/wiki/RSA_cryptosystem

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{convert::Infallible, fmt};

use serde::{de::Error as _, ser::Error as _, Deserialize, Serialize};

use super::backend::{
    interface::{
        self,
        rsa::{self, BigIntRef, PrivateKey as _, PublicKey as _},
    },
    Backend,
};
use crate::{
    base64_url::Base64UrlBytes,
    crypto::Result,
    jwa::{self, RsaSigning},
    jwk::{self, FromKey, IntoJsonWebKey},
    jws::{self, InvalidSigningAlgorithmError},
};

type BackendPublicKey = <Backend as interface::Backend>::RsaPublicKey;
type BackendPrivateKey = <Backend as interface::Backend>::RsaPrivateKey;
type BigInt = <BackendPrivateKey as rsa::PrivateKey>::BigInt;

/// The returned signature from a sign operation.
#[repr(transparent)]
pub struct Signature {
    inner: <BackendPrivateKey as rsa::PrivateKey>::Signature,
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Self {
        value.as_ref().to_vec()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

/// The RSA public key type.
#[derive(Clone)]
pub struct PublicKey {
    inner: BackendPublicKey,
}

impl Eq for PublicKey {}
impl PartialEq for PublicKey {
    fn eq(&self, o: &Self) -> bool {
        self.inner.n() == o.inner.n() && self.inner.e() == o.inner.e()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("n", &self.inner.n())
            .field("e", &self.inner.e())
            .finish()
    }
}

impl From<PublicKey> for jwk::JsonWebKeyType {
    fn from(x: PublicKey) -> Self {
        jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Public(
            jwk::Public::Rsa(x),
        )))
    }
}

impl crate::sealed::Sealed for PublicKey {}
impl IntoJsonWebKey for PublicKey {
    type Algorithm = RsaSigning;
    type Error = Infallible;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let alg = alg.map(|rsa| {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(rsa.into()))
        });

        let key = jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Public(
            jwk::Public::Rsa(self),
        )));

        Ok(jwk::JsonWebKey::new_with_algorithm(key, alg))
    }
}

impl jwk::Thumbprint for PublicKey {
    fn thumbprint_prehashed(&self) -> String {
        crate::jwk::thumbprint::serialize_key_thumbprint(self)
    }
}

impl Serialize for PublicKey {
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
            n: Base64UrlBytes(BigIntRef::to_bytes_be(self.inner.n())),
            e: Base64UrlBytes(BigIntRef::to_bytes_be(self.inner.e())),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
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

        let components = rsa::PublicKeyComponents {
            n: repr.n.0,
            e: repr.e.0,
        };
        let key = BackendPublicKey::from_components(components)
            .map_err(|e| D::Error::custom(format!("failed to construct RSA public key: {}", e)))?;
        Ok(Self { inner: key })
    }
}

/// The RSA private key type.
#[derive(Clone)]
pub struct PrivateKey {
    inner: BackendPrivateKey,
}

impl PrivateKey {
    /// Generate a new RSA key pair of the given bit size.
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if the key generation fails.
    pub fn generate() -> Result<Self> {
        todo!()
    }

    /// Get the public key corresponding to this private key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }
}

impl Eq for PrivateKey {}
impl PartialEq for PrivateKey {
    fn eq(&self, o: &Self) -> bool {
        self.to_public_key() == o.to_public_key()
    }
}

impl From<PrivateKey> for jwk::JsonWebKeyType {
    fn from(x: PrivateKey) -> Self {
        jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Private(
            jwk::Private::Rsa(Box::new(x)),
        )))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("n", &self.inner.n())
            .field("e", &self.inner.e())
            .field("primes", &"[REDACTED]")
            .finish()
    }
}

impl crate::sealed::Sealed for PrivateKey {}
impl IntoJsonWebKey for PrivateKey {
    type Algorithm = RsaSigning;
    type Error = Infallible;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let alg = alg.map(|rsa| {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(rsa.into()))
        });

        let key = jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Private(
            jwk::Private::Rsa(Box::new(self)),
        )));

        Ok(crate::JsonWebKey::new_with_algorithm(key, alg))
    }
}

impl jwk::Thumbprint for PrivateKey {
    fn thumbprint_prehashed(&self) -> String {
        self.to_public_key().thumbprint_prehashed()
    }
}

impl Serialize for PrivateKey {
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

        let dp = Base64UrlBytes(self.inner.dp().to_bytes_be());
        let dq = Base64UrlBytes(self.inner.dq().to_bytes_be());
        let qi = Base64UrlBytes(self.inner.qi().to_bytes_be());

        let d = Base64UrlBytes(self.inner.d().to_bytes_be());

        let n = Base64UrlBytes(self.inner.n().to_bytes_be());
        let e = Base64UrlBytes(self.inner.e().to_bytes_be());

        let [p, q]: [BigInt; 2] = self
            .inner
            .primes()
            .try_into()
            .map_err(|_| S::Error::custom("expected exactly two primes for RSA private key"))?;

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

impl<'de> Deserialize<'de> for PrivateKey {
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

        // RFC:
        //
        // The parameter "d" is REQUIRED for RSA private keys.  The others enable
        // optimizations and SHOULD be included by producers of JWKs
        // representing RSA private keys.  If the producer includes any of the
        // other private key parameters, then all of the others MUST be present,
        // with the exception of "oth", which MUST only be present when more than two
        // prime factors were used.

        let any_prime_present = repr.p.is_some()
            | repr.q.is_some()
            | repr.dp.is_some()
            | repr.dq.is_some()
            | repr.qi.is_some();

        // let all_primes_present = [
        //     ("p", repr.p.is_some()),
        //     ("q", repr.q.is_some()),
        //     ("dp", repr.dp.is_some()),
        //     ("dq", repr.dq.is_some()),
        //     ("qi", repr.qi.is_some()),
        // ];

        let prime_info = if any_prime_present {
            let err = |field: &str| {
                D::Error::custom(format!(
                    "expected `{}` to be present because all prime fields must be set if one of \
                     them is set",
                    field
                ))
            };

            rsa::PrivateKeyPrimeComponents {
                p: repr.p.ok_or_else(|| err("p"))?.0,
                q: repr.q.ok_or_else(|| err("q"))?.0,
                dp: repr.dp.ok_or_else(|| err("dp"))?.0,
                dq: repr.dq.ok_or_else(|| err("dq"))?.0,
                qi: repr.qi.ok_or_else(|| err("qi"))?.0,
            }
        } else {
            // FIXME: can we support RSA keys without any primes?
            return Err(D::Error::custom(
                "RSA private keys without any primes are not supported",
            ));
        };

        if repr.oth.is_some() {
            // FIXME: Support additional primes
            return Err(D::Error::custom(
                "RSA private keys with `oth` field set are not supported",
            ));
        }

        let components = rsa::PrivateKeyComponents {
            public: rsa::PublicKeyComponents {
                n: repr.n.0,
                e: repr.e.0,
            },
            d: repr.d.0,
            prime: prime_info,
        };

        let key = BackendPrivateKey::from_components(components)
            .map_err(|e| D::Error::custom(format!("failed to construct RSA private key: {e}")))?;
        Ok(Self { inner: key })
    }
}

/// A [`Signer`](jws::Signer) using an [`PrivateKey`] and an RSA algorithm.
#[derive(Debug)]
pub struct Signer {
    key: PrivateKey,
    alg: RsaSigning,
}

impl FromKey<PrivateKey> for Signer {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(value: PrivateKey, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(alg)) => {
                Ok(Self { key: value, alg })
            }
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

impl jws::Signer<Signature> for Signer {
    fn sign(&mut self, msg: &[u8]) -> Result<Signature> {
        let sig = self.key.inner.sign(self.alg, msg)?;
        Ok(Signature { inner: sig })
    }

    fn algorithm(&self) -> jwa::JsonWebSigningAlgorithm {
        jwa::JsonWebSigningAlgorithm::Rsa(self.alg)
    }
}

/// A [`Verifier`](jws::Verifier) using an [`PublicKey`] and an RSA algorithm.
#[derive(Debug)]
pub struct Verifier {
    key: PublicKey,
    alg: RsaSigning,
}

impl FromKey<PublicKey> for Verifier {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(value: PublicKey, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Rsa(alg)) => {
                Ok(Self { key: value, alg })
            }
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

impl FromKey<PrivateKey> for Verifier {
    type Error = InvalidSigningAlgorithmError;

    /// Create a [`Verifier`] from the private key by
    /// turning it into the public key and dropping the private parts afterwards
    fn from_key(value: PrivateKey, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        Self::from_key(value.to_public_key(), alg)
    }
}

impl jws::Verifier for Verifier {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), jws::VerifyError> {
        match self.key.inner.verify(self.alg, msg, signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(jws::VerifyError::InvalidSignature),
            Err(err) => Err(jws::VerifyError::CryptoBackend(err)),
        }
    }
}
