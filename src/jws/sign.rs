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
/// A message is signed using a [`Signer`] by first getting an instance of a
/// digest using the [`new_digest`] method. Then the whole message is put into
/// the returned digest using the [`digest::Update`] trait bound, and to finally
/// get the signature, one uses the [`finalize`] method.
///
/// To be able to be used as a [`Signer`], one must provide the sign operation
/// itself, and also needs to [specify the algorithm] used for signing. The
/// algorithm will be used as the value for the `alg` field inside the
/// [`JoseHeader`](crate::jws::JoseHeader) for the signed type.
///
/// [`new_digest`]: Signer::new_digest
/// [`finalize`]: Signer::finalize
/// [specify the algorithm]: Signer::algorithm
pub trait Signer<S: AsRef<[u8]>> {
    /// The [`Digest`](digest::Digest) for this signer that will be used to
    /// create the hash.
    type Digest: digest::Update;

    /// Create a new instance of digest for this signer.
    fn new_digest(&self) -> Self::Digest;

    /// Signs a pre-hashed message that was created using the digest for this
    /// siger.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    /// An error usually only appears when communicating with external signers.
    fn sign_digest(&mut self, digest: Self::Digest) -> Result<S, signature::Error>;

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
#[derive(Debug, thiserror_no_std::Error, PartialEq, Eq)]
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
