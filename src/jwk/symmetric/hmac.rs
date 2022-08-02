//! Hmac cryptography.

use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use digest::{FixedOutput, FixedOutputReset, KeyInit, Output, OutputSizeUser, Update};
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

    /// The [`hmac::Hmac`] type for this variant.
    type HmacType: Clone + KeyInit + FixedOutput + FixedOutputReset + Update + fmt::Debug;
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
            alg: H::HmacType::new(&key),
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
        alg: impl Into<Option<Self::Algorithm>>,
    ) -> Result<crate::JsonWebKey, Self::Error> {
        let key = jwk::JsonWebKeyType::Symmetric(jwk::SymmetricJsonWebKey::OctetSequence(
            OctetSequence::new(self.key),
        ));

        let mut jwk = crate::JsonWebKey::new(key);
        jwk.algorithm = alg
            .into()
            .map(|_| jwa::JsonWebAlgorithm::Signing(H::ALGORITHM));
        Ok(jwk)
    }
}

impl<H: HmacVariant> Verifier for HmacKey<H> {
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
        // FIXME: use the verify method from the `digest::Mac` trait instead then it has
        // a method which does not consume self. See <https://github.com/RustCrypto/traits/issues/1050>
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
    type Digest = H::HmacType;

    fn new_digest(&self) -> Self::Digest {
        self.alg.clone()
    }

    fn sign_digest(&mut self, digest: Self::Digest) -> Result<HmacSignature<H>, signature::Error> {
        let out = digest.finalize_fixed();
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
                if key.len() < <<H::HmacType as OutputSizeUser>::OutputSize as Unsigned>::USIZE {
                    return Err(digest::InvalidLength.into());
                }

                let hmac = H::HmacType::new_from_slice(key)
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

                let hmac = H::HmacType::new_from_slice(&value.0 .0)
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
