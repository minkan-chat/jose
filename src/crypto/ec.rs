//! The primitives for working with [EC (elliptic curve)](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
//! algorithms (`kty` parameter = `EC`).
//!
//! If you are looking for the other curve types, see the
//! [`okp`](crate::crypto::okp) module, which contains all curves that require a
//! octet key pair.

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{fmt, marker::PhantomData};

use serde::{de::Error as _, Deserialize, Serialize};

use super::backend::{interface, Backend};
use crate::{
    base64_url::Base64UrlBytes,
    crypto::{
        backend::interface::ec::{PrivateKey as _, PublicKey as _},
        Result,
    },
    jwa, jwk, jws, Base64UrlString,
};

type BackendPublicKey = <Backend as interface::Backend>::EcPublicKey;
type BackendPrivateKey = <Backend as interface::Backend>::EcPrivateKey;

/// The public key type using the P-256 curve.
pub type P256PublicKey = PublicKey<P256>;

/// The private key type using the P-256 curve.
pub type P256PrivateKey = PrivateKey<P256>;

/// The signer type using the P-256 curve.
pub type P256Signer = Signer<P256>;

/// The verifier type using the P-256 curve.
pub type P256Verifier = Verifier<P256>;

/// The public key type using the P-384 curve.
pub type P384PublicKey = PublicKey<P384>;

/// The private key type using the P-384 curve.
pub type P384PrivateKey = PrivateKey<P384>;

/// The signer type using the P-384 curve.
pub type P384Signer = Signer<P384>;

/// The verifier type using the P-384 curve.
pub type P384Verifier = Verifier<P384>;

/// The public key type using the P-521 curve.
pub type P521PublicKey = PublicKey<P521>;

/// The private key type using the P-521 curve.
pub type P521PrivateKey = PrivateKey<P521>;

/// The signer type using the P-521 curve.
pub type P521Signer = Signer<P521>;

/// The verifier type using the P-521 curve.
pub type P521Verifier = Verifier<P521>;

/// The public key type using the secp256k1 curve.
pub type Secp256k1PublicKey = PublicKey<Secp256k1>;

/// The private key type using the secp256k1 curve.
pub type Secp256k1PrivateKey = PrivateKey<Secp256k1>;

/// The signer type using the secp256k1 curve.
pub type Secp256k1Signer = Signer<Secp256k1>;

/// The verifier type using the secp256k1 curve.
pub type Secp256k1Verifier = Verifier<Secp256k1>;

/// The curve trait marks all possible curves for key type `EC`.
pub trait Curve: sealed::Sealed {
    /// The name of the curve, that is also used in the `crv` parameter of a
    /// JWK.
    const NAME: &'static str;

    /// The algorithm used for this curve.
    const ALGORITHM: jwa::EcDSA;
}

/// The returned signature from a sign operation.
#[repr(transparent)]
pub struct Signature {
    inner: <BackendPrivateKey as interface::ec::PrivateKey>::Signature,
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
        fmt::Debug::fmt(AsRef::<[u8]>::as_ref(&self.inner), f)
    }
}

/// The serializable public key for all curve types.
#[derive(Clone)]
pub struct PublicKey<C> {
    inner: BackendPublicKey,
    _curve: PhantomData<C>,
}

impl<C: Curve> Eq for PublicKey<C> {}
impl<C: Curve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        let (x, y) = self.inner.to_point();
        let (o_x, o_y) = other.inner.to_point();

        x == o_x && y == o_y
    }
}

impl<C: Curve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (x, y) = self.inner.to_point();
        let x = Base64UrlString::encode(x);
        let y = Base64UrlString::encode(y);

        f.debug_struct("PublicKey")
            .field("x", &x)
            .field("y", &y)
            .finish()
    }
}

impl<C: Curve> From<PublicKey<C>> for jwk::JsonWebKeyType {
    fn from(value: PublicKey<C>) -> Self {
        C::public_to_jwk_type(value)
    }
}

impl<C: Curve> crate::sealed::Sealed for PublicKey<C> {}
impl<C: Curve> jwk::IntoJsonWebKey for PublicKey<C> {
    type Algorithm = ();
    type Error = crate::crypto::Error;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<jwk::JsonWebKey, Self::Error> {
        let key = C::public_to_jwk_type(self);
        let key = jwk::JsonWebKey::new_with_algorithm(key, alg.map(|_| C::ALGORITHM.into()));
        Ok(key)
    }
}

impl<C: Curve> jwk::Thumbprint for PublicKey<C> {
    fn thumbprint_prehashed(&self) -> String {
        jwk::thumbprint::serialize_key_thumbprint(self)
    }
}

#[derive(Deserialize)]
struct PublicKeyRepr {
    crv: String,
    kty: String,
    x: Base64UrlBytes,
    y: Base64UrlBytes,
}

impl<'de, C: Curve> Deserialize<'de> for PublicKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = PublicKeyRepr::deserialize(deserializer)?;

        if key.kty != "EC" {
            return Err(D::Error::custom(alloc::format!(
                "Invalid key type `{}`. Expected: `EC`",
                key.kty,
            )));
        }

        if key.crv != C::NAME {
            return Err(D::Error::custom(alloc::format!(
                "Invalid curve type `{}`. Expected: `{}`",
                key.crv,
                C::NAME,
            )));
        }

        Ok(Self {
            inner: <BackendPublicKey as interface::ec::PublicKey>::new(
                C::ALGORITHM,
                key.x.0,
                key.y.0,
            )
            .map_err(|e| D::Error::custom(format!("failed to construct public EC key: {e}")))?,
            _curve: PhantomData,
        })
    }
}

impl<C: Curve> Serialize for PublicKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct Repr<'a> {
            crv: &'a str,
            kty: &'a str,
            x: Base64UrlBytes,
            y: Base64UrlBytes,
        }

        let (x, y) = self.inner.to_point();

        #[expect(clippy::useless_conversion)]
        let repr = Repr {
            crv: C::NAME,
            kty: "EC",
            x: Base64UrlBytes(Vec::<u8>::from(x)),
            y: Base64UrlBytes(Vec::<u8>::from(y)),
        };

        repr.serialize(serializer)
    }
}

/// The serializable private key for all curve types.
#[derive(Clone)]
pub struct PrivateKey<C> {
    inner: BackendPrivateKey,
    _curve: PhantomData<C>,
}

impl<C: Curve> PrivateKey<C> {
    /// Generate a new RSA key pair of the given bit size.
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] if the key generation fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            inner: BackendPrivateKey::generate(C::ALGORITHM)?,
            _curve: PhantomData,
        })
    }

    /// Returns the public key of this private key.
    pub fn to_public_key(&self) -> PublicKey<C> {
        PublicKey {
            inner: self.inner.to_public_key(),
            _curve: PhantomData,
        }
    }
}

impl<C: Curve> Eq for PrivateKey<C> {}
impl<C: Curve> PartialEq for PrivateKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.to_public_key() == other.to_public_key()
    }
}

impl<C: Curve> fmt::Debug for PrivateKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (x, y) = self.inner.public_point();
        let x = Base64UrlString::encode(x);
        let y = Base64UrlString::encode(y);

        f.debug_struct("PublicKey")
            .field("x", &x)
            .field("y", &y)
            .field("d", &"[REDACTED]")
            .finish()
    }
}

impl<C: Curve> From<PrivateKey<C>> for jwk::JsonWebKeyType {
    fn from(value: PrivateKey<C>) -> Self {
        C::private_to_jwk_type(value)
    }
}

impl<C: Curve> crate::sealed::Sealed for PrivateKey<C> {}
impl<C: Curve> jwk::IntoJsonWebKey for PrivateKey<C> {
    type Algorithm = ();
    type Error = crate::crypto::Error;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<jwk::JsonWebKey, Self::Error> {
        let key = C::private_to_jwk_type(self);
        let key = jwk::JsonWebKey::new_with_algorithm(key, alg.map(|_| C::ALGORITHM.into()));
        Ok(key)
    }
}

impl<C: Curve> jwk::Thumbprint for PrivateKey<C> {
    fn thumbprint_prehashed(&self) -> String {
        self.to_public_key().thumbprint_prehashed()
    }
}

impl<'de, C: Curve> Deserialize<'de> for PrivateKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            #[serde(flatten)]
            public: PublicKeyRepr,
            d: Base64UrlBytes,
        }
        let key = Repr::deserialize(deserializer)?;

        Ok(Self {
            inner: <BackendPrivateKey as interface::ec::PrivateKey>::new(
                C::ALGORITHM,
                key.public.x.0,
                key.public.y.0,
                key.d.0,
            )
            .map_err(|e| D::Error::custom(format!("failed to construct private EC key: {e}")))?,
            _curve: PhantomData,
        })
    }
}

impl<C: Curve> Serialize for PrivateKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct Repr<'a> {
            crv: &'a str,
            kty: &'a str,
            x: Base64UrlBytes,
            y: Base64UrlBytes,
            d: Base64UrlBytes,
        }

        let (x, y) = self.inner.public_point();
        let d = self.inner.private_material();

        #[expect(clippy::useless_conversion)]
        let repr = Repr {
            crv: C::NAME,
            kty: "EC",
            x: Base64UrlBytes(Vec::<u8>::from(x)),
            y: Base64UrlBytes(Vec::<u8>::from(y)),
            d: Base64UrlBytes(Vec::<u8>::from(d)),
        };

        repr.serialize(serializer)
    }
}

/// The [`Signer`](jws::Signer) for EC keys.
pub struct Signer<C> {
    inner: PrivateKey<C>,
    deterministic: bool,
}

impl<C: Curve> Signer<C> {
    /// Makes the sign operation of this EcDSA signer deterministic.
    ///
    /// This enables deterministic signature values, according to [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).
    pub fn deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;
        self
    }
}

impl<C: Curve> fmt::Debug for Signer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer").field("key", &self.inner).finish()
    }
}

impl<C: Curve> jws::Signer<Signature> for Signer<C> {
    fn sign(&mut self, msg: &[u8]) -> Result<Signature> {
        let sig = self.inner.inner.sign(msg, self.deterministic)?;
        Ok(Signature { inner: sig })
    }

    fn algorithm(&self) -> jwa::JsonWebSigningAlgorithm {
        jwa::JsonWebSigningAlgorithm::EcDSA(C::ALGORITHM)
    }
}

impl<C: Curve> jwk::FromKey<PrivateKey<C>> for Signer<C> {
    type Error = jws::InvalidSigningAlgorithmError;

    fn from_key(value: PrivateKey<C>, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::EcDSA(alg))
                if alg == C::ALGORITHM =>
            {
                Ok(Self {
                    inner: value,
                    deterministic: false,
                })
            }
            _ => Err(jws::InvalidSigningAlgorithmError),
        }
    }
}

/// The [`Verifier`](jws::Verifier) for EC keys.
pub struct Verifier<C> {
    inner: PublicKey<C>,
}

impl<C: Curve> fmt::Debug for Verifier<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("key", &self.inner)
            .finish()
    }
}

impl<C: Curve> jws::Verifier for Verifier<C> {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), jws::VerifyError> {
        match self.inner.inner.verify(msg, signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(jws::VerifyError::InvalidSignature),
            Err(e) => Err(jws::VerifyError::CryptoBackend(e)),
        }
    }
}

impl<C: Curve> jwk::FromKey<PublicKey<C>> for Verifier<C> {
    type Error = jws::InvalidSigningAlgorithmError;

    fn from_key(value: PublicKey<C>, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::EcDSA(alg))
                if alg == C::ALGORITHM =>
            {
                Ok(Self { inner: value })
            }
            _ => Err(jws::InvalidSigningAlgorithmError),
        }
    }
}

impl<C: Curve> jwk::FromKey<PrivateKey<C>> for Verifier<C> {
    type Error = jws::InvalidSigningAlgorithmError;

    #[inline]
    fn from_key(value: PrivateKey<C>, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        Self::from_key(value.to_public_key(), alg)
    }
}

macro_rules! impl_curve {
    ($(
        $(#[$doc:meta])*
        $curve:ident {
            name: $curve_name:literal,
            algorithm: $algorithm:ident,
        }
    ),*$(,)?) => { $(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy)]
        pub enum $curve {}

        impl Curve for $curve {
            const NAME: &'static str = $curve_name;
            const ALGORITHM: jwa::EcDSA = jwa::EcDSA::$algorithm;
        }
        impl sealed::Sealed for $curve {
            fn public_to_jwk_type(key: PublicKey<Self>) -> jwk::JsonWebKeyType {
                jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Public(
                    jwk::Public::Ec(jwk::EcPublic::$curve(key)),
                )))
            }

            fn private_to_jwk_type(key: PrivateKey<Self>) -> jwk::JsonWebKeyType {
                jwk::JsonWebKeyType::Asymmetric(Box::new(jwk::AsymmetricJsonWebKey::Private(
                    jwk::Private::Ec(jwk::EcPrivate::$curve(key)),
                )))
            }
        }
    )* };
}

impl_curve!(
    /// The P-256 curve.
    P256 {
        name: "P-256",
        algorithm: Es256,
    },

    /// The P-384 curve.
    P384 {
        name: "P-384",
        algorithm: Es384,
    },

    /// The P-521 curve.
    P521 {
        name: "P-521",
        algorithm: Es512,
    },

    /// The secp256k1 curve.
    Secp256k1 {
        name: "secp256k1",
        algorithm: Es256K,
    },
);

mod sealed {
    use crate::jwk::JsonWebKeyType;

    pub trait Sealed: Sized {
        fn public_to_jwk_type(key: super::PublicKey<Self>) -> JsonWebKeyType;

        fn private_to_jwk_type(key: super::PrivateKey<Self>) -> JsonWebKeyType;
    }
}
