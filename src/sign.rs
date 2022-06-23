use alloc::string::String;

use crate::{
    format::{AppendSignature, IntoFormat},
    jwa::JsonWebSigningAlgorithm,
};

pub(crate) mod sealed {
    pub trait Sealed {
        type Value;
    }
}

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
pub struct Signed<T: sealed::Sealed, S> {
    pub(crate) value: T::Value,
    pub(crate) signature: S,
}

impl<T: sealed::Sealed, S: AsRef<[u8]>> Signed<T, S> {
    /// Encodes this signed value into the given format (`F`).
    ///
    /// Available formats are [`JsonFlattened`](crate::format::JsonFlattened)
    /// and [`Compact`](crate::format::Compact).
    pub fn encode<F>(self) -> F
    where
        T::Value: IntoFormat<F>,
        F: AppendSignature,
    {
        let mut format = self.value.into_format();
        format.append_signature(self.signature.as_ref());
        format
    }
}

/// Implemented for anything that can be using a [`Signer`].
pub trait Signable: Sized + sealed::Sealed {
    /// The error that can occurr while signing.
    type Error;

    /// Sign `self` using the given signer and return a [signed](Signed) version
    /// of `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign<S: AsRef<[u8]>>(
        self,
        signer: &mut dyn Signer<S>,
    ) -> Result<Signed<Self, S>, Self::Error>;
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
    fn key_id(&self) -> Option<String> {
        None
    }
}

/// An error used if [`FromKey`] or [`IntoSigner`] expected a different
/// algorithm
#[derive(Debug, thiserror_no_std::Error)]
#[error("Invalid algorithm")]
pub struct InvalidSigningAlgorithmError;

/// A trait for a [`Signer`] to implement if it can be created from key material
/// as long as the algorithm is known
pub trait FromKey<K, S>: Signer<S> + Sized
where
    S: AsRef<[u8]>,
{
    /// The error returned if the conversion failed
    type Error;

    /// Turn `K` into this [`Signer`].
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion failed
    fn from_key(value: K, alg: JsonWebSigningAlgorithm) -> Result<Self, Self::Error>;
}

/// A trait to turn something into a [`Signer`].
///
/// Some key types like the [`Rsa`](crate::jwk::rsa::RsaPrivateKey) key type
/// need to know which [algorithm](JsonWebSigningAlgorithm) to use.
pub trait IntoSigner<T, S>
where
    T: Signer<S>,
    S: AsRef<[u8]>,
{
    /// The error returned if the version failed
    type Error;

    /// Turn `self` into the [`Signer`] `T`
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion failed
    fn into_signer(self, alg: JsonWebSigningAlgorithm) -> Result<T, Self::Error>;
}

impl<A, T, S> IntoSigner<T, S> for A
where
    T: FromKey<A, S>,
    S: AsRef<[u8]>,
{
    type Error = <T as FromKey<A, S>>::Error;

    fn into_signer(self, alg: JsonWebSigningAlgorithm) -> Result<T, Self::Error> {
        T::from_key(self, alg)
    }
}
