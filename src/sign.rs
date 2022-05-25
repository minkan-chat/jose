use alloc::string::String;

use crate::{
    format::{AppendToFormat, IntoFormat},
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

impl<T: sealed::Sealed, S> Signed<T, S> {
    /// Encodes this signed value into the given format (`F`).
    ///
    /// Available formats are [`Json`](crate::format::Json) and
    /// [`Compact`](crate::format::Compact).
    pub fn encode<F>(self) -> F
    where
        T::Value: IntoFormat<F>,
        S: AppendToFormat<F>,
    {
        let mut format = self.value.into_format();
        self.signature.append_to(&mut format);
        format
    }
}

/// Implemented for anything that can be using a [`Signer`].
pub trait Signable: Sized + sealed::Sealed {
    /// The error that can occurr while signing.
    type Error;

    /// Sign `self` using the given signer and return a [signed](Signed) version
    /// of `self`.
    fn sign<S: AsRef<[u8]>>(self, signer: &dyn Signer<S>) -> Result<Signed<Self, S>, Self::Error>;
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
    fn sign(&self, msg: &[u8]) -> Result<S, signature::Error>;

    /// Return the type of signing algorithm used by this signer.
    fn algorithm(&self) -> JsonWebSigningAlgorithm;

    /// JsonWebSignatures *can* contain a key id which is specified
    /// by this method.
    fn key_id(&self) -> Option<String> {
        None
    }
}
