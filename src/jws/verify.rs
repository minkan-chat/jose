use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use thiserror::Error;

use super::JsonWebSignature;
use crate::{
    crypto,
    format::{DecodeFormat, DecodeFormatWithContext, Format, JsonGeneral},
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::FromKey,
};

/// The error indicating if either the signature is invalid, or if the
/// cyptographic operation failed.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The signature is invalid.
    #[error("signature is invalid")]
    InvalidSignature,

    /// The crypto backend threw an error.
    #[error("crypto backend error")]
    CryptoBackend(
        #[from]
        #[source]
        crypto::Error,
    ),
}

/// This trait represents anything that can be used to verify a JWS, JWE, or
/// whatever.
pub trait Verifier {
    /// The `verify` operation.
    ///
    /// If the message is valid, returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`signature::Error`] if anything went wrong during signature
    /// verification or if the signature is just invalid.
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), VerifyError>;
}

/// This wrapper type represents a [JWS](crate::JsonWebSignature) that was
/// parsed from user input, but the data integrity was not verified, thus it
/// might contain corrupted or malicious data.
///
/// An [`Unverified`] struct can be verified using the [`verify`](Self::verify)
/// method.
#[derive(Debug)]
pub struct Unverified<T> {
    pub(crate) value: T,
    pub(crate) signature: Vec<u8>,
    pub(crate) msg: Vec<u8>,
}

impl<T> Unverified<T> {
    /// Parse the input format to an unverified representation of `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// the `T` type.
    pub fn decode<F: Format>(input: F) -> Result<Self, T::Error>
    where
        T: DecodeFormat<F, Decoded<T> = Unverified<T>>,
    {
        T::decode(input)
    }

    /// Parse the input format to an unverified representation of `T`, with the
    /// given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// the `T` type.
    pub fn decode_with_context<F: Format, C>(input: F, context: &C) -> Result<Self, T::Error>
    where
        T: DecodeFormatWithContext<F, C, Decoded<T> = Unverified<T>>,
    {
        T::decode_with_context(input, context)
    }

    /// Verify this struct using the given verifier, returning a [`Verified`]
    /// representation of the inner type.
    ///
    /// # Errors
    ///
    /// Returns [`signature::Error`] if anything went wrong during signature
    /// verification or if the signature is just invalid.
    pub fn verify(self, verifier: &mut dyn Verifier) -> Result<Verified<T>, VerifyError> {
        verifier.verify(&self.msg, &self.signature)?;
        Ok(Verified(self.value))
    }
}

impl<T, F> Unverified<JsonWebSignature<F, T>>
where
    F: Format,
{
    /// Exposes the **unverified** [`JoseHeader`](crate::JoseHeader) of this
    /// [`JsonWebSignature`]
    ///
    /// You usually **should not use this method**. Instead, verify the
    /// [`JsonWebSignature`] and potentially protected headers first, to avoid
    /// creating security vulnerabilities.
    ///
    /// # When to use
    ///
    /// One use case is to determine which key was used to create this signature
    /// in the first place. For example, consider you have a list of public
    /// keys used by the same party. If you were not able to peek inside to
    /// get a hint of the key used, for example via
    /// [`JoseHeader::key_identifier`](crate::JoseHeader::key_identifier), you
    /// would have to try each key until either a signature is valid or
    /// there are no keys left.
    ///
    /// However, note that, since the header is not verified yet, an attacker
    /// can spoof the key hint. For example, you MUST still make sure that the
    /// key in the hint is actually established and does not belong to some
    /// other party which might still be in your list of keys but is unrelated.
    ///
    /// # Security
    ///
    /// Every security garantee given by this crate is broken for the returned
    /// [`JoseHeader`](crate::JoseHeader), including
    /// [`HeaderValue::Protected`](crate::header::HeaderValue). Thus, you should
    /// use this method only within isolated code regions.
    pub fn expose_unverified_header(&self) -> &F::JwsHeader {
        &self.value.header
    }

    /// Exposes the **unverified** [`payload`](JsonWebSignature::payload) of
    /// this [`JsonWebSignature`]
    ///
    /// You **should never have the need to use this method**. If you have
    /// information in the payload that you need in order to verify the
    /// signature, you are using it wrong. Instead, such information should be
    /// put in the [`JoseHeader`](crate::JoseHeader) and can be accessed via
    /// [`expose_unverified_header]`](Self::expose_unverified_header).
    ///
    /// # Security
    ///
    /// Every security garantee given by this crate is broken for the returned
    /// payload `T`. Thus, you should use this method only within isolated code
    /// regions.
    pub fn expose_unverified_payload(&self) -> &T {
        &self.value.payload
    }

    /// Exposes the **unverified** raw signature in its byte representation
    ///
    /// Note: raw means that it is already base64 decoded.
    ///
    /// There is absolutely no reason to use this method. If you want to use
    /// your own code for verification, you should create your own [`Verifier`]
    /// instead.
    pub fn expose_unverified_raw_signature(&self) -> &[u8] {
        self.signature.as_slice()
    }
}

/// This wrapper type represents a [JWS](crate::JsonWebSignature) that was
/// parsed from user input, but the data integrity was not verified, thus it
/// might contain corrupted or malicious data.
///
/// Compared to [`Unverified`] this type can contain multiple signatures that
/// need to be verified. An instance of this type can only be obtained by
/// decoding a JWS using the [`JsonGeneral`] format.
#[derive(Debug)]
pub struct ManyUnverified<T> {
    pub(crate) value: T,
    // Vec<(msg, signature)>
    pub(crate) signatures: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<T> ManyUnverified<T> {
    /// Parses a JWS in the [`JsonGeneral`] format into an unverified
    /// representation of `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// the `T` type.
    pub fn decode(input: JsonGeneral) -> Result<Self, T::Error>
    where
        T: DecodeFormat<JsonGeneral, Decoded<T> = ManyUnverified<T>>,
    {
        T::decode(input)
    }

    /// Returns the number of signatures in this JWS.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Verify this struct using the given verifies, returning a [`Verified`]
    /// representation of the inner type.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of verifiers does not match the number of
    /// signatures, or if anything went wrong during a signature
    /// verification or if one of the signatures is just invalid.
    // TODO: consider using a more specific error type to give the usermore
    // information about the error
    pub fn verify_many<'a>(
        self,
        verifiers: impl IntoIterator<Item = &'a mut dyn Verifier>,
    ) -> Result<Verified<T>, VerifyError> {
        let verifiers = verifiers.into_iter().collect::<Vec<_>>();
        if verifiers.len() != self.signatures.len() {
            return Err(VerifyError::InvalidSignature);
        }

        for (verifier, (msg, signature)) in verifiers.into_iter().zip(self.signatures) {
            verifier.verify(&msg, &signature)?;
        }

        Ok(Verified(self.value))
    }
}

impl<T, F> ManyUnverified<JsonWebSignature<F, T>>
where
    F: Format,
{
    /// Exposes the **unverified** [`JoseHeader`](crate::JoseHeader) of this
    /// [`JsonWebSignature`]
    ///
    /// You usually **should not use this method**. Instead, verify the
    /// [`JsonWebSignature`] and potentially protected headers first, to avoid
    /// creating security vulnerabilities.
    ///
    /// # When to use
    ///
    /// One use case is to determine which key was used to create this signature
    /// in the first place. For example, consider you have a list of public
    /// keys used by the same party. If you were not able to peek inside to
    /// get a hint of the key used, for example via
    /// [`JoseHeader::key_identifier`](crate::JoseHeader::key_identifier), you
    /// would have to try each key until either a signature is valid or
    /// there are no keys left.
    ///
    /// However, note that, since the header is not verified yet, an attacker
    /// can spoof the key hint. For example, you MUST still make sure that the
    /// key in the hint is actually established and does not belong to some
    /// other party which might still be in your list of keys but is unrelated.
    ///
    /// # Security
    ///
    /// Every security garantee given by this crate is broken for the returned
    /// [`JoseHeader`](crate::JoseHeader), including
    /// [`HeaderValue::Protected`](crate::header::HeaderValue). Thus, you should
    /// use this method only within isolated code regions.
    pub fn expose_unverified_header(&self) -> &F::JwsHeader {
        &self.value.header
    }

    /// Exposes the **unverified** [`payload`](JsonWebSignature::payload) of
    /// this [`JsonWebSignature`]
    ///
    /// You **should never have the need to use this method**. If you have
    /// information in the payload that you need in order to verify the
    /// signature, you are using it wrong. Instead, such information should be
    /// put in the [`JoseHeader`](crate::JoseHeader) and can be accessed via
    /// [`expose_unverified_header]`](Self::expose_unverified_header).
    ///
    /// # Security
    ///
    /// Every security garantee given by this crate is broken for the returned
    /// payload `T`. Thus, you should use this method only within isolated code
    /// regions.
    pub fn expose_unverified_payload(&self) -> &T {
        &self.value.payload
    }

    /// Exposes an [`Iterator`] over the **unverified** signatures and their
    /// corresponding messages.
    ///
    /// It returns an [`Iterator`] over `(message, signature)` for each
    /// signature. Note: raw means that they are already base64 decoded.
    ///
    /// There is absolutely no reason to use this method. If you want to use
    /// your own code for verification, you should create your own [`Verifier`]
    /// instead.
    pub fn expose_unverified_raw_signatures(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.signatures
            .iter()
            .map(|(msg, sig)| (msg.as_slice(), sig.as_slice()))
    }
}

/// Wrapper type around a JWS, or JWE that was verified using a [`Verifier`].
#[derive(Debug)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// Turns self into it's inner `T`.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Verified<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A trait to turn something into a [`Verifier`]
///
/// Some key types like the [`Rsa`](crate::crypto::rsa::PublicKey) key type need
/// to know which [algorithm](JsonWebSigningAlgorithm) to use.
pub trait IntoVerifier<V>
where
    V: Verifier,
{
    /// The error returned if the conversion failed
    type Error;

    /// Turn `self` into the [`Verifier`] `V`
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion failed
    fn into_verifier(self, alg: JsonWebSigningAlgorithm) -> Result<V, Self::Error>;
}

impl<K, V> IntoVerifier<V> for K
where
    V: FromKey<K> + Verifier,
{
    type Error = <V as FromKey<K>>::Error;

    fn into_verifier(self, alg: JsonWebSigningAlgorithm) -> Result<V, Self::Error> {
        V::from_key(self, JsonWebAlgorithm::Signing(alg))
    }
}
