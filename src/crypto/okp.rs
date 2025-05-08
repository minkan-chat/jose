//! The primitives for working with EdDSA algorithms (`kty`
//! parameter = `OKP`).
//!
//! If you are looking for the other curve types, see the
//! [`ec`](crate::crypto::ec) module, which contains all curves, that do not
//! require an octet key pair as a key.

use alloc::{borrow::Cow, format, string::String, vec::Vec};
use core::{fmt, marker::PhantomData};

use secrecy::SecretSlice;
use serde::{de::Error as _, Deserialize, Serialize};
use zeroize::Zeroizing;

use super::backend::{
    interface::{
        self,
        okp::{PrivateKey as _, PublicKey as _},
    },
    Backend,
};
use crate::{crypto::Result, jwa, jwk, jws, Base64UrlString};

const KTY: &str = "OKP";

type BackendPublicKey = <Backend as interface::Backend>::EdPublicKey;
type BackendPrivateKey = <Backend as interface::Backend>::EdPrivateKey;

/// The curve trait marks all possible curves for EdDSA keys.
///
/// Technically, the implementors of this trait (e.g. [`Ed25519`]) are not
/// curves, but rather the curve + algorithm combination. However, the JWK
/// specification uses the term "curve" for this combination, so we will
/// follow that convention here.
pub trait Curve: sealed::Sealed {
    /// The name of the curve, that is also used in the `crv` parameter of a
    /// JWK.
    const NAME: &'static str;
}

/// The public key using the Ed25519 curve.
pub type Ed25519PublicKey = PublicKey<Ed25519>;

/// The private key using the Ed25519 curve.
pub type Ed25519PrivateKey = PrivateKey<Ed25519>;

/// The signer type using the Ed25519 curve.
pub type Ed25519Signer = Signer<Ed25519>;

/// The verifier type using the Ed25519 curve.
pub type Ed25519Verifier = Verifier<Ed25519>;

/// The public key using the Ed448 curve.
pub type Ed448PublicKey = PublicKey<Ed448>;

/// The private key using the Ed448 curve.
pub type Ed448PrivateKey = PrivateKey<Ed448>;

/// The signer type using the Ed448 curve.
pub type Ed448Signer = Signer<Ed448>;

/// The verifier type using the Ed448 curve.
pub type Ed448Verifier = Verifier<Ed448>;

/// The returned signature from a sign operation.
#[repr(transparent)]
pub struct Signature {
    inner: <BackendPrivateKey as interface::okp::PrivateKey>::Signature,
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

/// A public key for EdDSA algorithms.
///
/// The type of algorithm and curve is determined by the
/// `C` type parameter.
#[derive(Clone)]
pub struct PublicKey<C> {
    inner: BackendPublicKey,
    _curve: PhantomData<C>,
}

impl<C: Curve> Eq for PublicKey<C> {}
impl<C: Curve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        interface::okp::PublicKey::as_bytes(&self.inner)
            == interface::okp::PublicKey::as_bytes(&other.inner)
    }
}

impl<C: Curve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = Base64UrlString::encode(interface::okp::PublicKey::as_bytes(&self.inner));
        f.debug_struct("PublicKey")
            .field("curve", &C::NAME)
            .field("x", &bytes)
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
        let key = jwk::JsonWebKey::new_with_algorithm(
            key,
            alg.map(|_| jwa::JsonWebSigningAlgorithm::EdDSA.into()),
        );
        Ok(key)
    }
}

impl<C: Curve> jwk::Thumbprint for PublicKey<C> {
    fn thumbprint_prehashed(&self) -> String {
        jwk::thumbprint::serialize_key_thumbprint(self)
    }
}

#[derive(Serialize, Deserialize)]
struct PublicRepr<'a> {
    crv: Cow<'a, str>,
    kty: Cow<'a, str>,
    x: Base64UrlString,
}

impl<'de, C: Curve> Deserialize<'de> for PublicKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = PublicRepr::deserialize(deserializer)?;

        if repr.crv != C::NAME {
            return Err(D::Error::custom(format!(
                "Invalid curve type `{}`. Expected `{}`",
                repr.crv,
                C::NAME
            )));
        }

        if repr.kty != KTY {
            return Err(D::Error::custom(format!(
                "Invalid key type `{}`. Expected `{KTY}`",
                repr.kty,
            )));
        }

        let x = repr.x.decode();
        let key = interface::okp::PublicKey::new(C::ALGORITHM, x).map_err(D::Error::custom)?;
        Ok(Self {
            inner: key,
            _curve: PhantomData,
        })
    }
}

impl<C: Curve> Serialize for PublicKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let repr = PublicRepr {
            crv: C::NAME.into(),
            kty: KTY.into(),
            x: Base64UrlString::encode(interface::okp::PublicKey::as_bytes(&self.inner)),
        };

        repr.serialize(serializer)
    }
}

/// A private key for EdDSA algorithms.
///
/// The type of algorithm and curve is determined by the
/// `C` type parameter.
#[derive(Clone)]
pub struct PrivateKey<C> {
    inner: BackendPrivateKey,
    _curve: PhantomData<C>,
}

impl<C: Curve> PrivateKey<C> {
    /// Generate a new random key pair.
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
        let pub_key = interface::okp::PrivateKey::to_public_key(&self.inner);
        let bytes = Base64UrlString::encode(interface::okp::PublicKey::as_bytes(&pub_key));

        f.debug_struct("PrivateKey")
            .field("curve", &C::NAME)
            .field("x", &bytes)
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
        let key = jwk::JsonWebKey::new_with_algorithm(
            key,
            alg.map(|_| jwa::JsonWebSigningAlgorithm::EdDSA.into()),
        );
        Ok(key)
    }
}

impl<C: Curve> jwk::Thumbprint for PrivateKey<C> {
    fn thumbprint_prehashed(&self) -> String {
        self.to_public_key().thumbprint_prehashed()
    }
}

#[derive(Serialize, Deserialize)]
struct PrivateRepr<'a> {
    #[serde(flatten)]
    public: PublicRepr<'a>,
    d: Zeroizing<Base64UrlString>,
}

impl<'de, C: Curve> Deserialize<'de> for PrivateKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = PrivateRepr::deserialize(deserializer)?;

        let x = repr.public.x.decode();
        let d = SecretSlice::from(repr.d.decode());
        let key = interface::okp::PrivateKey::new(C::ALGORITHM, x, d).map_err(D::Error::custom)?;

        Ok(Self {
            inner: key,
            _curve: PhantomData,
        })
    }
}

impl<C: Curve> Serialize for PrivateKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pub_key = self.inner.to_public_key();
        let repr = PrivateRepr {
            public: PublicRepr {
                crv: C::NAME.into(),
                kty: KTY.into(),
                x: Base64UrlString::encode(interface::okp::PublicKey::as_bytes(&pub_key)),
            },
            d: Zeroizing::new(Base64UrlString::encode(
                interface::okp::PrivateKey::as_bytes(&self.inner),
            )),
        };

        repr.serialize(serializer)
    }
}

/// The [`Signer`](jws::Signer) for EC keys.
pub struct Signer<C> {
    inner: PrivateKey<C>,
}

impl<C: Curve> fmt::Debug for Signer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer").field("key", &self.inner).finish()
    }
}

impl<C: Curve> jws::Signer<Signature> for Signer<C> {
    fn sign(&mut self, msg: &[u8]) -> Result<Signature> {
        let sig = self.inner.inner.sign(msg)?;
        Ok(Signature { inner: sig })
    }

    fn algorithm(&self) -> jwa::JsonWebSigningAlgorithm {
        jwa::JsonWebSigningAlgorithm::EdDSA
    }
}

impl<C: Curve> jwk::FromKey<PrivateKey<C>> for Signer<C> {
    type Error = jws::InvalidSigningAlgorithmError;

    fn from_key(value: PrivateKey<C>, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::EdDSA) => {
                Ok(Self { inner: value })
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
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::EdDSA) => {
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
        }
    ),*$(,)?) => { $(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy)]
        pub enum $curve {}

        impl Curve for $curve {
            const NAME: &'static str = $curve_name;
        }

        impl sealed::Sealed for $curve {
            #[expect(private_interfaces)]
            const ALGORITHM: interface::okp::CurveAlgorithm = interface::okp::CurveAlgorithm::$curve;

            fn public_to_jwk_type(key: PublicKey<Self>) -> jwk::JsonWebKeyType {
                jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(jwk::AsymmetricJsonWebKey::Public(
                    jwk::Public::Okp(jwk::OkpPublic::$curve(key)),
                )))
            }

            fn private_to_jwk_type(key: PrivateKey<Self>) -> jwk::JsonWebKeyType {
                jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(jwk::AsymmetricJsonWebKey::Private(
                    jwk::Private::Okp(jwk::OkpPrivate::$curve(key)),
                )))
            }
        }
    )* };
}

impl_curve!(
    /// The Ed25519 curve.
    Ed25519 {
        name: "Ed25519",
    },

    /// The Ed448 curve.
    Ed448 {
        name: "Ed448",
    },
);

mod sealed {
    use crate::{crypto::backend::interface, jwk::JsonWebKeyType};

    pub trait Sealed: Sized {
        #[expect(private_interfaces)]
        const ALGORITHM: interface::okp::CurveAlgorithm;

        fn public_to_jwk_type(key: super::PublicKey<Self>) -> JsonWebKeyType;

        fn private_to_jwk_type(key: super::PrivateKey<Self>) -> JsonWebKeyType;
    }
}
