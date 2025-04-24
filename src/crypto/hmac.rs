//! The primitives for working with [HMAC] algorithms.
//!
//! [HMAC]: https://en.wikipedia.org/wiki/HMAC

use core::fmt;

use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq as _;

use super::{
    backend::{
        interface::{self, hmac::Key as _},
        Backend,
    },
    Error, Result,
};
use crate::{
    crypto::backend::interface::Backend as _,
    jwa,
    jwk::{
        self,
        symmetric::{FromOctetSequenceError, OctetSequence},
        IntoJsonWebKey,
    },
    jws::{self, Signer},
};

type BackendHmacKey = <Backend as interface::Backend>::HmacKey;

/// Marker trait is implemented for all supported HMAC variants.
pub trait Variant: crate::sealed::Sealed {
    /// The JWA algorithm for this variant.
    const ALGORITHM: jwa::Hmac;

    /// The number of bytes in the output of the hash operation operation.
    const OUTPUT_SIZE_BYTES: usize;
}

/// The returned signature from a sign operation.
#[repr(transparent)]
pub struct Signature {
    inner: <BackendHmacKey as interface::hmac::Key>::Signature,
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

/// A key that can be used for signing and verifying HMAC signatures.
pub struct Key<H: Variant> {
    inner: BackendHmacKey,
    // We also need to store the raw key, to be able to convert it to a JWK.
    raw_key: SecretBox<[u8]>,
    _variant: core::marker::PhantomData<H>,
}

impl<H: Variant> Key<H> {
    /// Generate a new random HMAC key, using the crypto backends default RNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the crypto backend failed to generate random data.
    pub fn generate() -> Result<Self> {
        let mut key = alloc::vec![0u8; H::OUTPUT_SIZE_BYTES].into_boxed_slice();
        Backend::fill_random(&mut key)?;
        let key = SecretBox::new(key);

        Self::new_from_key(key)
    }

    fn new_from_key(key: SecretBox<[u8]>) -> Result<Self> {
        let inner = BackendHmacKey::new(H::ALGORITHM, key.expose_secret())?;
        Ok(Self {
            inner,
            raw_key: key,
            _variant: core::marker::PhantomData,
        })
    }
}

impl<H: Variant> fmt::Debug for Key<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("key", &self.raw_key)
            .field("algorithm", &H::ALGORITHM)
            .finish()
    }
}

impl<H: Variant> From<Key<H>> for jwk::JsonWebKeyType {
    fn from(key: Key<H>) -> Self {
        jwk::JsonWebKeyType::Symmetric(jwk::SymmetricJsonWebKey::OctetSequence(OctetSequence::new(
            key.raw_key,
        )))
    }
}

impl<H: Variant> crate::sealed::Sealed for Key<H> {}
impl<H: Variant> IntoJsonWebKey for Key<H> {
    type Algorithm = ();
    type Error = core::convert::Infallible;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let key_ty = jwk::JsonWebKeyType::from(self);
        let alg = alg.map(|_| {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Hmac(H::ALGORITHM))
        });
        Ok(jwk::JsonWebKey::new_with_algorithm(key_ty, alg))
    }
}

impl<H: Variant> jws::Verifier for Key<H> {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), jws::VerifyError> {
        let signed = self.inner.sign(msg)?;

        let valid = bool::from(signature.ct_eq(signed.as_ref()));
        if valid {
            Ok(())
        } else {
            Err(jws::VerifyError::InvalidSignature)
        }
    }
}

impl<H: Variant> Signer<Signature> for Key<H> {
    fn sign(&mut self, msg: &[u8]) -> Result<Signature, Error> {
        let signature = self.inner.sign(msg)?;
        Ok(Signature { inner: signature })
    }

    fn algorithm(&self) -> jwa::JsonWebSigningAlgorithm {
        jwa::JsonWebSigningAlgorithm::Hmac(H::ALGORITHM)
    }
}

impl<H: Variant> jwk::FromKey<&OctetSequence> for Key<H> {
    type Error = FromOctetSequenceError;

    fn from_key(key: &OctetSequence, alg: jwa::JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            jwa::JsonWebAlgorithm::Signing(jwa::JsonWebSigningAlgorithm::Hmac(alg)) => {
                if alg != H::ALGORITHM {
                    return Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                        jws::InvalidSigningAlgorithmError,
                    ));
                }

                // This check is not required for normal Hmac implementations based on RFC 2104
                // // but RFC 7518 section 3.2 requires this check and
                // forbids keys with a length < output
                if key.len() < H::OUTPUT_SIZE_BYTES {
                    return Err(FromOctetSequenceError::InvalidLength);
                }

                Ok(Self::new_from_key(key.bytes().clone())?)
            }
            _ => Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                jws::InvalidSigningAlgorithmError,
            )),
        }
    }
}
macro_rules! impl_variant {
    (#[$doc:meta] $variant:ident = $size:expr) => {
        #[$doc]
        #[derive(Debug)]
        pub enum $variant {}

        impl Variant for $variant {
            const ALGORITHM: jwa::Hmac = jwa::Hmac::$variant;
            const OUTPUT_SIZE_BYTES: usize = $size;
        }
        impl crate::sealed::Sealed for $variant {}
    };
}

impl_variant!(
    /// Marker type that represents Hmac using the Sha256 digest.
    Hs256 = 256 / 8
);
impl_variant!(
    /// Marker type that represents Hmac using the Sha384 digest.
    Hs384 = 384 / 8
);
impl_variant!(
    /// Marker type that represents Hmac using the Sha512 digest.
    Hs512 = 512 / 8
);
