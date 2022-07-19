//! Hmac cryptography.

use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use digest::{FixedOutputReset, KeyInit, Output, Update};

use super::{FromOctetSequenceError, OctetSequence};
use crate::{
    jwa::{self, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::FromKey,
    jws::{Signer, Verifier},
    sealed::Sealed,
};

/// Represents all supported Hmac variants.
pub trait HmacVariant: Sealed {
    /// The JWA algorithm for this variant.
    const ALGORITHM: JsonWebSigningAlgorithm;

    /// The [`hmac::Hmac`] type for this variant.
    type HmacType: KeyInit + FixedOutputReset + Update + fmt::Debug;

    /// The signature type for this algorithm.
    type Signature: AsRef<[u8]>;
}

/// Marker type that represents Hmac using the Sha256 digest.
#[derive(Debug)]
pub struct Hs256 {}

impl Sealed for Hs256 {}
impl HmacVariant for Hs256 {
    type HmacType = hmac::Hmac<sha2::Sha256>;
    type Signature = [u8; 0];

    const ALGORITHM: JsonWebSigningAlgorithm = JsonWebSigningAlgorithm::Hmac(jwa::Hmac::Hs256);
}

/// Marker type that represents Hmac using the Sha384 digest.
#[derive(Debug)]
pub struct Hs384 {}

impl Sealed for Hs384 {}
impl HmacVariant for Hs384 {
    type HmacType = hmac::Hmac<sha2::Sha384>;
    type Signature = [u8; 0];

    const ALGORITHM: JsonWebSigningAlgorithm = JsonWebSigningAlgorithm::Hmac(jwa::Hmac::Hs384);
}

/// Marker type that represents Hmac using the Sha512 digest.
#[derive(Debug)]
pub struct Hs512 {}

impl Sealed for Hs512 {}
impl HmacVariant for Hs512 {
    type HmacType = hmac::Hmac<sha2::Sha512>;
    type Signature = [u8; 0];

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
/// At the same time this key implements [`Signer`] and [`Verifier`], thus
/// can be used to sign and verify JWSs.
#[derive(Debug)]
#[repr(transparent)]
pub struct HmacKey<H: HmacVariant> {
    alg: H::HmacType,
}

impl<H: HmacVariant> Verifier for HmacKey<H> {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
        // FIXME: use the verify method from the `digest::Mac` trait instead then it has
        // a method which does not consume self
        self.alg.update(msg);

        // the signature that this Hmac would calculate
        let expected = self.alg.finalize_fixed_reset();

        // constant time check to avoid potential leakage
        use subtle::ConstantTimeEq as _;

        // this u8 is 1 for true, 0 for false
        match expected.ct_eq(signature).unwrap_u8() {
            1 => Ok(()),
            _ => Err(signature::Error::new()),
        }
    }
}

impl<H: HmacVariant> Signer<HmacSignature<H>> for HmacKey<H> {
    fn sign(&mut self, msg: &[u8]) -> Result<HmacSignature<H>, signature::Error> {
        self.alg.update(msg);
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

                let hmac = H::HmacType::new_from_slice(&value.0)
                    .map_err(|e| FromOctetSequenceError::InvalidLength(e))?;
                Ok(Self { alg: hmac })
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
        <HmacKey<H> as FromKey<&OctetSequence>>::from_key(&value, alg)
    }
}
