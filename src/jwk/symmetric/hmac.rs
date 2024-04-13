//! Hmac cryptography.

use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use digest::{FixedOutputReset, KeyInit, Mac, Output, OutputSizeUser, Update};
use typenum::Unsigned;

use super::{FromOctetSequenceError, OctetSequence};
use crate::{
    jwa::{self, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::{self, FromKey, IntoJsonWebKey},
    jws::{Signer, Verifier},
    sealed::Sealed,
};

/// Represents all supported Hmac variants.
pub trait HmacVariant: Sealed {
    /// The JWA algorithm for this variant.
    const ALGORITHM: JsonWebSigningAlgorithm;

    /// The output size of this HMAC variant in bytes.
    const OUTPUT_SIZE: usize = <<Self::HmacType as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

    /// The [`hmac::Hmac`] type for this variant.
    type HmacType: Mac + FixedOutputReset + KeyInit + fmt::Debug;
}

/// Marker type that represents Hmac using the Sha256 digest.
#[derive(Debug)]
pub struct Hs256 {}

impl Sealed for Hs256 {}
impl HmacVariant for Hs256 {
    type HmacType = hmac::Hmac<sha2::Sha256>;

    const ALGORITHM: JsonWebSigningAlgorithm = JsonWebSigningAlgorithm::Hmac(jwa::Hmac::Hs256);
}

/// Marker type that represents Hmac using the Sha384 digest.
#[derive(Debug)]
pub struct Hs384 {}

impl Sealed for Hs384 {}
impl HmacVariant for Hs384 {
    type HmacType = hmac::Hmac<sha2::Sha384>;

    const ALGORITHM: JsonWebSigningAlgorithm = JsonWebSigningAlgorithm::Hmac(jwa::Hmac::Hs384);
}

/// Marker type that represents Hmac using the Sha512 digest.
#[derive(Debug)]
pub struct Hs512 {}

impl Sealed for Hs512 {}
impl HmacVariant for Hs512 {
    type HmacType = hmac::Hmac<sha2::Sha512>;

    const ALGORITHM: JsonWebSigningAlgorithm = JsonWebSigningAlgorithm::Hmac(jwa::Hmac::Hs512);
}

/// The signature for a specific Hmac variant.
#[derive(Debug)]
#[repr(transparent)]
pub struct HmacSignature<H: HmacVariant>(Output<H::HmacType>);

impl<H: HmacVariant> Deref for HmacSignature<H> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<H: HmacVariant> DerefMut for HmacSignature<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<H: HmacVariant> AsRef<[u8]> for HmacSignature<H> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A generic key for any Hmac variant ([`Hs256`], [`Hs384`], [`Hs512`]).
///
/// Since hmac uses a [symmetric key](super::SymmetricJsonWebKey), this struct
/// implements both [`Signer`] and [`Verifier`]
#[derive(Debug)]
pub struct HmacKey<H: HmacVariant> {
    alg: H::HmacType,
    key: Vec<u8>,
}

impl<H: HmacVariant> HmacKey<H> {
    /// Generate a new HMAC key.
    pub fn generate(mut rng: impl rand_core::CryptoRng + rand_core::RngCore) -> Self {
        let mut key = digest::Key::<H::HmacType>::default();
        rng.fill_bytes(&mut key);

        HmacKey {
            alg: <H::HmacType as KeyInit>::new(&key),
            key: key.to_vec(),
        }
    }
}

impl<H: HmacVariant> From<HmacKey<H>> for jwk::JsonWebKeyType {
    fn from(key: HmacKey<H>) -> Self {
        jwk::JsonWebKeyType::Symmetric(jwk::SymmetricJsonWebKey::OctetSequence(OctetSequence::new(
            key.key,
        )))
    }
}

impl<H: HmacVariant> Sealed for HmacKey<H> {}
impl<H: HmacVariant> IntoJsonWebKey for HmacKey<H> {
    type Algorithm = ();
    type Error = core::convert::Infallible;

    fn into_jwk(
        self,
        alg: Option<impl Into<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let key = jwk::JsonWebKeyType::Symmetric(jwk::SymmetricJsonWebKey::OctetSequence(
            OctetSequence::new(self.key),
        ));

        let mut jwk = crate::JsonWebKey::new(key);
        jwk.algorithm = alg.map(|_| JsonWebAlgorithm::Signing(H::ALGORITHM));
        Ok(jwk)
    }
}

impl<H: HmacVariant> Verifier for HmacKey<H> {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
        <H::HmacType as Update>::update(&mut self.alg, msg);
        self.alg
            .verify_slice_reset(signature)
            .map_err(|_| signature::Error::new())
    }
}

impl<H: HmacVariant> Signer<HmacSignature<H>> for HmacKey<H> {
    fn sign(&mut self, msg: &[u8]) -> Result<HmacSignature<H>, signature::Error> {
        <H::HmacType as Update>::update(&mut self.alg, msg);
        let out = self.alg.finalize_fixed_reset();

        Ok(HmacSignature(out))
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        H::ALGORITHM
    }
}

impl<H: HmacVariant> FromKey<&OctetSequence> for HmacKey<H> {
    type Error = FromOctetSequenceError;

    fn from_key(value: &OctetSequence, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(alg) => {
                if alg != H::ALGORITHM {
                    return Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                        super::InvalidSigningAlgorithmError,
                    ));
                }

                let key = &value.0 .0;

                // This check is not required for normal Hmac implementations based on RFC 2104
                // but RFC 7518 section 3.2 requires this check and forbids keys with a length <
                // output
                if key.len() < <H as HmacVariant>::OUTPUT_SIZE {
                    return Err(digest::InvalidLength.into());
                }

                let hmac = <H::HmacType as KeyInit>::new_from_slice(key)
                    .map_err(FromOctetSequenceError::InvalidLength)?;
                Ok(Self {
                    alg: hmac,
                    key: value.0 .0.clone(),
                })
            }
            _ => Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                super::InvalidSigningAlgorithmError,
            )),
        }
    }
}

impl<H: HmacVariant> FromKey<OctetSequence> for HmacKey<H> {
    type Error = FromOctetSequenceError;

    fn from_key(value: OctetSequence, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(alg) => {
                if alg != H::ALGORITHM {
                    return Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                        super::InvalidSigningAlgorithmError,
                    ));
                }

                let hmac = <H::HmacType as KeyInit>::new_from_slice(&value.0 .0)
                    .map_err(FromOctetSequenceError::InvalidLength)?;
                Ok(Self {
                    alg: hmac,
                    key: value.0 .0,
                })
            }
            _ => Err(FromOctetSequenceError::InvalidSigningAlgorithm(
                super::InvalidSigningAlgorithmError,
            )),
        }
    }
}
