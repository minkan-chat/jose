use alloc::borrow::ToOwned;

use super::{
    private::EcPrivate, public::EcPublic, AsymmetricJsonWebKey, FromJwkError, FromKey, OkpPrivate,
    OkpPublic, Private, Public, SymmetricJsonWebKey,
};
use crate::{
    crypto::{ec, hmac, okp, rsa},
    jwa::{Hmac, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::{
        policy::{Checked, CryptographicOperation, Policy},
        JsonWebKeyType,
    },
    jws::{IntoVerifier, InvalidSigningAlgorithmError, Verifier, VerifyError},
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
                            EcPublic::P521(key) => InnerVerifier::Es512(key.into_verifier(alg)?),
                            EcPublic::Secp256k1(key) => {
                                InnerVerifier::Secp256k1(key.into_verifier(alg)?)
                            }
                        },
                        Public::Rsa(key) => InnerVerifier::Rsa(key.into_verifier(alg)?),
                        Public::Okp(key) => match key {
                            OkpPublic::Ed25519(key) => {
                                InnerVerifier::Ed25519(key.into_verifier(alg)?)
                            }
                            OkpPublic::Ed448(key) => InnerVerifier::Ed448(key.into_verifier(alg)?),
                        },
                    },
                    AsymmetricJsonWebKey::Private(key) => match key {
                        Private::Ec(key) => match key {
                            EcPrivate::P256(key) => InnerVerifier::Es256(key.into_verifier(alg)?),
                            EcPrivate::P384(key) => InnerVerifier::Es384(key.into_verifier(alg)?),
                            EcPrivate::P521(key) => InnerVerifier::Es512(key.into_verifier(alg)?),
                            EcPrivate::Secp256k1(key) => {
                                InnerVerifier::Secp256k1(key.into_verifier(alg)?)
                            }
                        },
                        Private::Rsa(key) => InnerVerifier::Rsa((*key).into_verifier(alg)?),
                        Private::Okp(key) => match key {
                            OkpPrivate::Ed25519(key) => {
                                InnerVerifier::Ed25519(key.into_verifier(alg)?)
                            }
                            OkpPrivate::Ed448(key) => InnerVerifier::Ed448(key.into_verifier(alg)?),
                        },
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
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        match &mut self.inner {
            InnerVerifier::Hs256(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Hs384(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Hs512(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Rsa(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Es256(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Es384(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Es512(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Secp256k1(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Ed448(verifier) => verifier.verify(msg, signature),
            InnerVerifier::Ed25519(verifier) => verifier.verify(msg, signature),
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
        let alg = jwk
            .algorithm()
            .ok_or(FromJwkError::InvalidAlgorithm)?
            .to_owned();
        JwkVerifier::from_key(jwk, alg)
    }
}
/// Abstract type with a variant for each [`Verifier`]
#[derive(Debug)]
enum InnerVerifier {
    // symmetric algorithms
    Hs256(hmac::Key<hmac::Hs256>),
    Hs384(hmac::Key<hmac::Hs384>),
    Hs512(hmac::Key<hmac::Hs512>),
    // asymmetric algorithms
    Rsa(rsa::Verifier),

    Es256(ec::P256Verifier),
    Es384(ec::P384Verifier),
    Es512(ec::P521Verifier),
    Secp256k1(ec::Secp256k1Verifier),

    Ed25519(okp::Ed25519Verifier),
    Ed448(okp::Ed448Verifier),
}
