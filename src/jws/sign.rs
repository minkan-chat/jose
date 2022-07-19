use super::JsonWebSignatureValue;
use crate::{
    format::{AppendSignature, IntoFormat},
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
pub struct Signed<S> {
    pub(crate) value: JsonWebSignatureValue,
    pub(crate) signature: S,
}

impl<S: AsRef<[u8]>> Signed<S> {
    /// Encodes this signed value into the given format (`F`).
    ///
    /// Available formats are [`JsonFlattened`](crate::format::JsonFlattened)
    /// and [`Compact`](crate::format::Compact).
    pub fn encode<F>(self) -> F
    where
        F: AppendSignature,
        JsonWebSignatureValue: IntoFormat<F>,
    {
        let mut format: F = self.value.into_format();
        format.append_signature(self.signature.as_ref());
        format
    }
}

/// This trait represents anything that can be used to sign a JWS, JWE, or
/// whatever.
///
/// To be able to be used as a [`Signer`], one must provide the [sign operation]
/// itself, and also needs to [specify the algorithm] used for signing. The
/// algorithm will be used as the value for the `alg` field inside the
/// [`JoseHeader`](crate::jws::JoseHeader) for the signed type.
///
/// [sign operation]: Signer::sign
/// [specify the algorithm]: Signer::algorithm
pub trait Signer<S: AsRef<[u8]>> {
    /// Sign the given bytestring using this signer and return the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    /// An error usually only appears when communicating with external signers.
    fn sign(&mut self, msg: &[u8]) -> Result<S, signature::Error>;

    /// Return the type of signing algorithm used by this signer.
    fn algorithm(&self) -> JsonWebSigningAlgorithm;

    /// JsonWebSignatures *can* contain a key id which is specified
    /// by this method.
    fn key_id(&self) -> Option<&str> {
        None
    }
}

/// An error returned if something expected a different
/// [`JsonWebAlgorithm`](crate::jwa::JsonWebAlgorithm)
#[derive(Debug, thiserror_no_std::Error)]
#[error("Invalid algorithm")]
pub struct InvalidSigningAlgorithmError;

/// A trait to turn something into a [`Signer`].
///
/// Some key types like the [`Rsa`](crate::jwk::rsa::RsaPrivateKey) key type
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
