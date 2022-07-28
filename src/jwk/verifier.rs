use super::{
    ec::{
        p256::P256Verifier, p384::P384Verifier, secp256k1::Secp256k1Verifier, EcPrivate, EcPublic,
    },
    symmetric::{self, hmac::HmacKey},
    AsymmetricJsonWebKey, FromJwkError, FromKey, Private, Public, SymmetricJsonWebKey,
};
use crate::{
    jwa::{Hmac, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::JsonWebKeyType,
    jws::{IntoVerifier, InvalidSigningAlgorithmError, Verifier},
    policy::{Checked, CryptographicOperation, Policy},
    JsonWebKey,
};
#[derive(Debug)]
/// An abstract [`Verifier`] over all possible [key types](JsonWebKeyType)
pub struct JwkVerifier {
    inner: InnerVerifier,
}

impl JwkVerifier {
    /// Create a [`JwkVerifier`] from a [`JsonWebKeyType`] used with the
    /// provided [`JsonWebAlgorithm`].
    ///
    /// # Errors
    ///
    /// This function returns an error if the provided [`JsonWebAlgorithm`] and
    /// the actual [`JsonWebKeyType`] don't match. Since this type is the
    /// counterpart to [`JwkSigner`](super::JwkSigner) it behaves almost
    /// identical. See it's error documentation for details.
    pub fn new(key: JsonWebKeyType, alg: JsonWebSigningAlgorithm) -> Result<Self, FromJwkError> {
        Ok(Self {
            inner: match key {
                JsonWebKeyType::Asymmetric(key) => match *key {
                    AsymmetricJsonWebKey::Public(key) => match key {
                        Public::Ec(key) => match key {
                            EcPublic::P256(key) => InnerVerifier::Es256(key.into_verifier(alg)?),
                            EcPublic::P384(key) => InnerVerifier::Es384(key.into_verifier(alg)?),
                            EcPublic::Secp256k1(key) => {
                                InnerVerifier::Secp256k1(key.into_verifier(alg)?)
                            }
                        },
                        Public::Rsa(_) => todo!(),
                    },
                    AsymmetricJsonWebKey::Private(key) => match key {
                        Private::Ec(key) => match key {
                            EcPrivate::P256(key) => InnerVerifier::Es256(key.into_verifier(alg)?),
                            EcPrivate::P384(key) => InnerVerifier::Es384(key.into_verifier(alg)?),
                            EcPrivate::Secp256k1(key) => {
                                InnerVerifier::Secp256k1(key.into_verifier(alg)?)
                            }
                        },
                        Private::Rsa(_) => todo!(),
                    },
                },
                JsonWebKeyType::Symmetric(key) => match key {
                    SymmetricJsonWebKey::OctetSequence(ref key) => match alg {
                        JsonWebSigningAlgorithm::Hmac(hs) => match hs {
                            Hmac::Hs256 => InnerVerifier::Hs256(key.into_verifier(alg)?),
                            Hmac::Hs384 => InnerVerifier::Hs384(key.into_verifier(alg)?),
                            Hmac::Hs512 => InnerVerifier::Hs512(key.into_verifier(alg)?),
                        },
                        _ => Err(InvalidSigningAlgorithmError)?,
                    },
                },
            },
        })
    }
}

impl Verifier for JwkVerifier {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
        match &mut self.inner {
            InnerVerifier::Hs256(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Hs384(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Hs512(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Es256(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Es384(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Secp256k1(verifier) => verifier.verify(msg, signature),
        }
    }
}

impl<T, P> FromKey<Checked<JsonWebKey<T>, P>> for JwkVerifier
where
    P: Policy,
{
    type Error = FromJwkError;

    /// Create a [`JwkVerifier`] form a [`JsonWebKey`] overwriting
    /// [`JsonWebKey::algorithm`] with `alg`.
    fn from_key(
        jwk: Checked<JsonWebKey<T>, P>,
        alg: JsonWebAlgorithm,
    ) -> Result<Self, Self::Error> {
        if let Some(usage) = jwk.key_usage() {
            jwk.policy()
                .may_perform_operation_key_use(CryptographicOperation::Verify, usage)
                .map_err(|_| FromJwkError::OperationNotAllowed)?
        }

        if let Some(ops) = jwk.key_operations() {
            jwk.policy()
                .may_perform_operation_key_ops(CryptographicOperation::Verify, ops)
                .map_err(|_| FromJwkError::OperationNotAllowed)?
        }

        match alg {
            JsonWebAlgorithm::Encryption(..) => Err(FromJwkError::InvalidAlgorithm),
            JsonWebAlgorithm::Signing(alg) => Self::new(jwk.into_type().key_type, alg),
        }
    }
}

impl<T, P> TryFrom<Checked<JsonWebKey<T>, P>> for JwkVerifier
where
    P: Policy,
{
    type Error = FromJwkError;

    /// Create a [`JwkVerifier`] from a [`JsonWebKey`]
    ///
    /// # Errors
    ///
    /// This conversion fails if [`JsonWebKey::algorithm`] is [`None`]
    fn try_from(jwk: Checked<JsonWebKey<T>, P>) -> Result<Self, Self::Error> {
        let alg = jwk.algorithm().ok_or(FromJwkError::InvalidAlgorithm)?;
        JwkVerifier::from_key(jwk, alg)
    }
}
/// Abstract type with a variant for each [`Verifier`]
#[derive(Debug)]
enum InnerVerifier {
    // symmetric algorithms
    Hs256(HmacKey<symmetric::hmac::Hs256>),
    Hs384(HmacKey<symmetric::hmac::Hs384>),
    Hs512(HmacKey<symmetric::hmac::Hs512>),
    // asymmetric algorithms
    // RSA not implemented yet
    Es256(P256Verifier),
    Es384(P384Verifier),
    Secp256k1(Secp256k1Verifier),
    // P-512 not supported yet
    // Curve-25519 and 448 not supported yet
}
