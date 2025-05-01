use core::fmt;

use crate::{
    crypto,
    format::sealed::SealedFormatJws,
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::FromKey,
};

/// This type indicates that the inner value is signed using a [signing
/// algorithm].
///
/// # Generic Arguments
///
/// - `T` is the inner type that is signed
/// - `S` is the signature
///
/// [signing algorithm]: crate::jwa::JsonWebSigningAlgorithm
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Signed<F> {
    pub(crate) value: F,
}

impl<F: SealedFormatJws<F>> fmt::Display for Signed<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, f)
    }
}

impl<F: SealedFormatJws<F>> Signed<F> {
    /// Encodes this signed value into the format of the signed JWS.
    #[inline]
    pub fn encode(self) -> F {
        self.value
    }
}

/// This trait represents anything that can be used to sign a JWS, JWE, or
/// whatever.
///
/// A message is signed by just passing the raw bytes that should be signed.
///
/// To be able to be used as a [`Signer`], one must provide the sign operation
/// itself, and also needs to [specify the algorithm] used for signing. The
/// algorithm will be used as the value for the `alg` field inside the
/// [`JoseHeader`](crate::header::JoseHeader) for the signed type.
///
/// [specify the algorithm]: Signer::algorithm
pub trait Signer<S: AsRef<[u8]>> {
    /// Signs a raw byte message using this signer, returning a signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    /// An error usually only appears when communicating with external signers.
    fn sign(&mut self, msg: &[u8]) -> Result<S, crypto::Error>;

    /// Return the type of signing algorithm used by this signer.
    fn algorithm(&self) -> JsonWebSigningAlgorithm;

    /// JsonWebSignatures *can* contain a key id which is specified
    /// by this method.
    fn key_id(&self) -> Option<&str> {
        None
    }

    /// Returns a new [`Signer`] that wraps `self`, but returns `None` when
    /// calling the `key_id` method.
    fn without_key_id(self) -> SignerWithoutKeyId<Self>
    where
        Self: Sized,
    {
        SignerWithoutKeyId { inner: self }
    }
}

/// Wrapper type around an existing [`Signer`] that will always return `None`
/// for the key id.
///
/// This is useful if you parse a JWK, which has a Key ID, but you do not want
/// to add this ID to the header in a JWS.
#[derive(Debug, Clone)]
pub struct SignerWithoutKeyId<S> {
    inner: S,
}

impl<SIG: AsRef<[u8]>, S: Signer<SIG>> Signer<SIG> for SignerWithoutKeyId<S> {
    fn sign(&mut self, msg: &[u8]) -> Result<SIG, crypto::Error> {
        S::sign(&mut self.inner, msg)
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        S::algorithm(&self.inner)
    }

    fn key_id(&self) -> Option<&str> {
        None
    }
}

/// An error returned if something expected a different
/// [`JsonWebAlgorithm`]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Invalid algorithm")]
pub struct InvalidSigningAlgorithmError;

/// A trait to turn something into a [`Signer`].
///
/// Some key types like the [`Rsa`](crate::crypto::rsa::PrivateKey) key type
/// need to know which [algorithm](JsonWebSigningAlgorithm) to use.
pub trait IntoSigner<T, S>
where
    T: Signer<S>,
    S: AsRef<[u8]>,
{
    /// The error returned if the conversion failed
    type Error;

    /// Turn `self` into the [`Signer`] `T`
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion failed
    fn into_signer(self, alg: JsonWebSigningAlgorithm) -> Result<T, Self::Error>;
}

impl<K, T, S> IntoSigner<T, S> for K
where
    T: FromKey<K> + Signer<S>,
    S: AsRef<[u8]>,
{
    type Error = <T as FromKey<K>>::Error;

    fn into_signer(self, alg: JsonWebSigningAlgorithm) -> Result<T, Self::Error> {
        T::from_key(self, JsonWebAlgorithm::Signing(alg))
    }
}
