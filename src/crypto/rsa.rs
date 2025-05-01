//! The primitives for working with [RSA] encryption.
//!
//! [RSA]: https://en.wikipedia.org/wiki/RSA_cryptosystem

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{convert::Infallible, fmt};

use serde::{de::Error as _, ser::Error as _, Deserialize, Serialize};

use super::backend::{
    interface::{
        self,
        rsa::{self, PrivateKey as _, PublicKey as _},
    },
    Backend,
};
use crate::{
    base64_url::{Base64UrlBytes, SecretBase64UrlBytes},
    crypto::Result,
    jwa::{self, RsaSigning},
    jwk::{self, FromKey, IntoJsonWebKey},
    jws::{self, InvalidSigningAlgorithmError},
    Base64UrlString,
};

type BackendPublicKey = <Backend as interface::Backend>::RsaPublicKey;
type BackendPrivateKey = <Backend as interface::Backend>::RsaPrivateKey;

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
        let this_pub = rsa::PublicKey::components(&self.inner);
        let o_pub = rsa::PublicKey::components(&o.inner);

        this_pub == o_pub
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = rsa::PublicKey::components(&self.inner);
        let n = Base64UrlString::encode(key.n);
        let e = Base64UrlString::encode(key.e);

        f.debug_struct("PublicKey")
            .field("n", &n)
            .field("e", &e)
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

        let key = rsa::PublicKey::components(&self.inner);
        Repr {
            kty: "RSA",
            n: Base64UrlBytes(key.n),
            e: Base64UrlBytes(key.e),
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
        let key = rsa::PublicKey::from_components(components)
            .map_err(|e| D::Error::custom(format!("failed to construct RSA public key: {e}")))?;
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
    pub fn generate(bits: usize) -> Result<Self> {
        let key = BackendPrivateKey::generate(bits)?;
        Ok(Self { inner: key })
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
        let key = rsa::PrivateKey::public_components(&self.inner);
        let n = Base64UrlString::encode(key.n);
        let e = Base64UrlString::encode(key.e);

        f.debug_struct("PrivateKey")
            .field("n", &n)
            .field("e", &e)
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

            d: SecretBase64UrlBytes,
            p: SecretBase64UrlBytes,
            q: SecretBase64UrlBytes,
            dp: SecretBase64UrlBytes,
            dq: SecretBase64UrlBytes,
            qi: SecretBase64UrlBytes,
        }

        let pub_key = rsa::PrivateKey::public_components(&self.inner);
        let key = rsa::PrivateKey::private_components(&self.inner).map_err(S::Error::custom)?;

        let repr = Repr {
            kty: "RSA",
            n: Base64UrlBytes(pub_key.n),
            e: Base64UrlBytes(pub_key.e),
            d: SecretBase64UrlBytes(key.d),
            p: SecretBase64UrlBytes(key.prime.p),
            q: SecretBase64UrlBytes(key.prime.q),
            dp: SecretBase64UrlBytes(key.prime.dp),
            dq: SecretBase64UrlBytes(key.prime.dq),
            qi: SecretBase64UrlBytes(key.prime.qi),
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
            d: SecretBase64UrlBytes,

            p: Option<SecretBase64UrlBytes>,
            q: Option<SecretBase64UrlBytes>,
            dp: Option<SecretBase64UrlBytes>,
            dq: Option<SecretBase64UrlBytes>,
            qi: Option<SecretBase64UrlBytes>,

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

        let prime_info = if any_prime_present {
            let err = |field: &str| {
                D::Error::custom(format!(
                    "expected `{field}` to be present because all prime fields must be set if one \
                     of them is set",
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

        let pub_components = rsa::PublicKeyComponents {
            n: repr.n.0,
            e: repr.e.0,
        };

        let priv_components = rsa::PrivateKeyComponents {
            d: repr.d.0,
            prime: prime_info,
        };

        let key = rsa::PrivateKey::from_components(priv_components, pub_components)
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
