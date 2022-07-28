use alloc::{string::String, vec::Vec};

use super::{
    ec::{p256::P256Signer, p384::P384Signer, secp256k1::Secp256k1Signer, EcPrivate},
    rsa::RsaSigner,
    symmetric::{
        hmac::{self, HmacKey},
        FromOctetSequenceError,
    },
    AsymmetricJsonWebKey, FromKey, JsonWebKeyType, Private, SymmetricJsonWebKey,
};
use crate::{
    jwa::{EcDSA, Hmac, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jws::{IntoSigner, InvalidSigningAlgorithmError, Signer},
    policy::{Checked, CryptographicOperation, Policy},
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
    ///     Err(FromJwkError::InvalidAlgorithm)
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
                            EcPrivate::Secp256k1(key) => {
                                InnerSigner::Secp256k1(key.into_signer(alg)?)
                            }
                        },
                        Private::Rsa(key) => InnerSigner::Rsa((*key).into_signer(alg)?),
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

    /// Sets the key id for this [`Signer`].
    ///
    /// If this method is used, the [`kid`] header of the signed JWS will be set
    /// to the given key id.
    ///
    /// [`kid`]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
    pub fn with_key_id(mut self, key_id: String) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Sets the key id of this signer to `None`.
    ///
    /// Calling this method will result to omitting the [`kid`] header in the
    /// signed JWS header.
    ///
    /// [`kid`]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
    pub fn without_key_id(mut self) -> Self {
        self.key_id = None;
        self
    }
}

impl Signer<Vec<u8>> for JwkSigner {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        match &mut self.inner {
            InnerSigner::Hs256(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Hs384(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Hs512(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Es256(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Es384(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Secp256k1(signer) => signer.sign(msg).map(|v| v.to_vec()),
            InnerSigner::Rsa(signer) => signer.sign(msg),
        }
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        match self.inner {
            InnerSigner::Hs256(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs256),
            InnerSigner::Hs384(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs384),
            InnerSigner::Hs512(_) => JsonWebSigningAlgorithm::Hmac(Hmac::Hs512),
            InnerSigner::Es256(_) => JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256),
            InnerSigner::Es384(_) => JsonWebSigningAlgorithm::EcDSA(EcDSA::Es384),
            InnerSigner::Secp256k1(_) => JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256K),
            InnerSigner::Rsa(ref rsa) => rsa.algorithm(),
        }
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

impl<T, P> TryFrom<Checked<JsonWebKey<T>, P>> for JwkSigner
where
    P: Policy,
{
    type Error = FromJwkError;

    /// Create a [`JwkSigner`] from a [`JsonWebKey`]
    ///
    /// # Errors
    ///
    /// This conversion fails if [`JsonWebKey::algorithm`] is [`None`]
    fn try_from(jwk: Checked<JsonWebKey<T>, P>) -> Result<Self, Self::Error> {
        let alg = jwk.algorithm().ok_or(FromJwkError::InvalidAlgorithm)?;
        let kid = jwk.kid.clone();
        let mut signer = JwkSigner::from_key(jwk, alg)?;
        signer.key_id = kid;
        Ok(signer)
    }
}

impl<T, P> FromKey<Checked<JsonWebKey<T>, P>> for JwkSigner
where
    P: Policy,
{
    type Error = FromJwkError;

    /// Create a [`JwkSigner`] from a [`JsonWebKey`] overwriting
    /// [`JsonWebKey::algorithm`] with `alg`.
    fn from_key(
        jwk: Checked<JsonWebKey<T>, P>,
        alg: JsonWebAlgorithm,
    ) -> Result<Self, Self::Error> {
        if let Some(usage) = jwk.key_usage() {
            jwk.policy()
                .may_perform_operation_key_use(CryptographicOperation::Sign, usage)
                .map_err(|_| FromJwkError::OperationNotAllowed)?
        }

        if let Some(ops) = jwk.key_operations() {
            jwk.policy()
                .may_perform_operation_key_ops(CryptographicOperation::Sign, ops)
                .map_err(|_| FromJwkError::OperationNotAllowed)?
        }

        match alg {
            JsonWebAlgorithm::Encryption(..) => Err(InvalidSigningAlgorithmError.into()),
            JsonWebAlgorithm::Signing(alg) => Self::new(jwk.into_type().key_type, alg),
        }
    }
}

/// An error returned when creating a [`JwkSigner`] from a [`JsonWebKeyType`]
/// (or indirectly via [`JsonWebKey`])
#[derive(Debug, thiserror_no_std::Error)]
#[non_exhaustive]
pub enum FromJwkError {
    /// A [`JsonWebKey`] has either the `use` or `key_ops` parameter set and one
    /// of these parameters indicates that this key MAY NOT be used for signing
    /// or verifying
    #[error("key not allowed for signing")]
    OperationNotAllowed,
    /// The algorithm can't be used with the provided [`JsonWebKeyType`]
    #[error("this algorithm can't be used together with this JsonWebKey")]
    InvalidAlgorithm,
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

impl From<InvalidSigningAlgorithmError> for FromJwkError {
    fn from(_: InvalidSigningAlgorithmError) -> Self {
        Self::InvalidAlgorithm
    }
}

/// Abstract type with a variant for each [`Signer`]
#[derive(Debug)]
enum InnerSigner {
    // symmetric algorithms
    Hs256(HmacKey<hmac::Hs256>),
    Hs384(HmacKey<hmac::Hs384>),
    Hs512(HmacKey<hmac::Hs512>),
    // asymmetric algorithms
    Rsa(RsaSigner),
    Es256(P256Signer),
    Es384(P384Signer),
    Secp256k1(Secp256k1Signer),
    // P-512 not supported yet
    // Curve-25519 and 448 not supported yet
}
