use alloc::{string::String, vec::Vec};

use super::{
    ec::{p256::P256Signer, p384::P384Signer, EcPrivate},
    symmetric::{FromOctetSequenceError, Hs256Signer, Hs384Signer, Hs512Signer},
    AsymmetricJsonWebKey, JsonWebKeyType, Private, SymmetricJsonWebKey,
};
use crate::{
    jwa::{EcDSA, Hmac, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jws::{IntoSigner, InvalidSigningAlgorithmError, Signer},
    policy::Checked,
    JsonWebKey,
};

/// An abstract [`Signer`] over all possible [key types](JsonWebKeyType)
// FIXME: make PR to dependencies to we can derive C-COMMON-TRAITS
#[derive(Debug)]
pub struct JwkSigner {
    inner: InnerSigner,
    key_id: Option<String>,
}

impl JwkSigner {
    /// Create a [`JwkSigner`] from a [`JsonWebKeyType`] used with the provided
    /// [`JsonWebAlgorithm`]
    ///
    /// # Errors
    ///
    /// This function returns an error if the provided [`JsonWebAlgorithm`] and
    /// the actual [`JsonWebKeyType`] don't match. For example, you'll get an
    /// error if you try to to use this function with a [symmetric
    /// key](JsonWebKeyType::Symmetric) and an asymmetric key algorithm.
    ///
    /// E.g., this won't work:
    ///     
    /// ```
    /// use jose::{
    ///     jwa::{Hmac, JsonWebSigningAlgorithm},
    ///     jwk::{FromJwkError, JsonWebKeyType, JwkSigner},
    /// };
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key: JsonWebKeyType = serde_json::from_str(
    ///     r#"
    /// {
    ///   "kty": "EC",
    ///   "kid": "6j1ImYAlN6DnVupozzN13UKnLR7BfEvngNmVl5bLlI0",
    ///   "crv": "P-256",
    ///   "x": "-HGJKqKLCoB6z4zlNKef927CODDulLcHdxNi2iUTi5g",
    ///   "y": "GaVhYaBvIgSAaNLjXjVqOvtCGH56x5s4DnWMy9TXbTU",
    ///   "d": "C6AV5ZvCGQevYYMJT15frXWuKaqEDthnSMtuJKEKykI"
    /// }"#,
    /// )?;
    ///
    /// // returns an error since a P-256 key cannot be used with Hmac
    /// assert!(matches!(
    ///     JwkSigner::new(key, JsonWebSigningAlgorithm::Hmac(Hmac::Hs256)),
    ///     Err(FromJwkError::InvalidAlgorithm(..))
    /// ));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(key: JsonWebKeyType, alg: JsonWebSigningAlgorithm) -> Result<Self, FromJwkError> {
        Ok(Self {
            key_id: None,
            inner: match key {
                JsonWebKeyType::Asymmetric(key) => match *key {
                    AsymmetricJsonWebKey::Public(_) => Err(FromJwkError::NoPrivateKey)?,
                    AsymmetricJsonWebKey::Private(key) => match key {
                        Private::Ec(key) => match key {
                            EcPrivate::P256(key) => InnerSigner::Es256(key.into_signer(alg)?),
                            EcPrivate::P384(key) => InnerSigner::Es384(key.into_signer(alg)?),
                            EcPrivate::Secp256k1(_) => todo!(),
                        },
                        Private::Rsa(_) => todo!(),
                    },
                },
                JsonWebKeyType::Symmetric(key) => match key {
                    SymmetricJsonWebKey::OctetSequence(ref key) => match alg {
                        JsonWebSigningAlgorithm::Hmac(hs) => match hs {
                            Hmac::Hs256 => InnerSigner::Hs256(key.into_signer(alg)?),
                            Hmac::Hs384 => InnerSigner::Hs384(key.into_signer(alg)?),
                            Hmac::Hs512 => InnerSigner::Hs512(key.into_signer(alg)?),
                        },
                        _ => Err(InvalidSigningAlgorithmError)?,
                    },
                },
            },
        })
    }
}

impl Signer<Vec<u8>> for JwkSigner {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        match &mut self.inner {
            InnerSigner::Hs256(signer) => signer.sign(msg).map(|v| v.into_iter().collect()),
            InnerSigner::Hs384(signer) => signer.sign(msg).map(|v| v.into_iter().collect()),
            InnerSigner::Hs512(signer) => signer.sign(msg).map(|v| v.into_iter().collect()),
            InnerSigner::Es256(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Es384(signer) => signer.sign(msg).map(|v| v.to_vec()),
        }
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        match self.inner {
            InnerSigner::Hs256(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs256),
            InnerSigner::Hs384(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs384),
            InnerSigner::Hs512(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs512),
            InnerSigner::Es256(_) => JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256),
            InnerSigner::Es384(_) => JsonWebSigningAlgorithm::EcDSA(EcDSA::Es384),
        }
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

impl<T, P> TryFrom<Checked<JsonWebKey<T>, P>> for JwkSigner {
    type Error = FromJwkError;

    /// Create a [`JwkSigner`] from a [`JsonWebKey`]
    ///
    /// # Errors
    ///
    /// This conversion fails if [`JsonWebKey::algorithm`] is [`None`]
    fn try_from(jwk: Checked<JsonWebKey<T>, P>) -> Result<Self, Self::Error> {
        let jwk = jwk.into_type();
        let alg = match jwk.algorithm().ok_or(InvalidSigningAlgorithmError)? {
            JsonWebAlgorithm::Encryption(_) => Err(InvalidSigningAlgorithmError)?,
            JsonWebAlgorithm::Signing(alg) => alg,
        };
        JwkSigner::new(jwk.key_type, alg)
    }
}
/// An error returned when creating a [`JwkSigner`] form a [`JsonWebKeyType`]
/// (or indirectly via [`JsonWebKey`])
#[derive(Debug, thiserror_no_std::Error)]
#[non_exhaustive]
pub enum FromJwkError {
    /// The algorithm can't be used with the provided [`JsonWebKeyType`]
    #[error(transparent)]
    InvalidAlgorithm(#[from] InvalidSigningAlgorithmError),
    /// The provided [`JsonWebKeyType`] did not contain a [private
    /// key](super::Private) which is needed by [`JwkSigner`] to create
    /// signatures.
    #[error("found variant which has no private key")]
    NoPrivateKey,
    /// See the documentation of [`FromOctetSequenceError`] for details.
    ///
    /// Usually, [`FromOctetSequenceError::InvalidLength`] shouldn't be returend
    /// since the key already exists at this point.
    #[error(transparent)]
    OctetSequence(#[from] FromOctetSequenceError),
}

/// Abstract type with a variant for each [`Signer`]
#[derive(Debug)]
enum InnerSigner {
    // symmetric algorithms
    Hs256(Hs256Signer),
    Hs384(Hs384Signer),
    Hs512(Hs512Signer),
    // asymmetric algorithms
    // RSA not implemented yet
    Es256(P256Signer),
    Es384(P384Signer),
    // P-512 not supported yet
    // Curve-25519 and 448 not supported yet
}
