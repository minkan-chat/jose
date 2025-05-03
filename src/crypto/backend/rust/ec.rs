use alloc::vec::Vec;

use ecdsa::EncodedPoint;
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint, ValidatePublicKey as _},
    FieldBytes, SecretKey,
};
use generic_array::typenum::Unsigned as _;
use k256::Secp256k1;
use p256::NistP256;
use p384::NistP384;
use rand_core::OsRng;
use secrecy::{ExposeSecret as _, SecretSlice};
use signature::{RandomizedSigner as _, Verifier as _};
use zeroize::Zeroizing;

use crate::{
    crypto::{backend::interface::ec, Result},
    jwa::{self, EcDSA},
};

#[derive(Clone)]
enum ErasedPrivateKey {
    P256 {
        key: SecretKey<NistP256>,
        public: EncodedPoint<NistP256>,
        d: Zeroizing<FieldBytes<NistP256>>,
    },
    P384 {
        key: SecretKey<NistP384>,
        public: EncodedPoint<NistP384>,
        d: Zeroizing<FieldBytes<NistP384>>,
    },
    Secp256k1 {
        key: SecretKey<Secp256k1>,
        public: EncodedPoint<Secp256k1>,
        d: Zeroizing<FieldBytes<Secp256k1>>,
    },
}

impl ErasedPrivateKey {
    fn new_p256(key: SecretKey<NistP256>) -> PrivateKey {
        PrivateKey {
            inner: Self::P256 {
                public: key.public_key().to_encoded_point(false),
                d: Zeroizing::new(key.to_bytes()),
                key,
            },
        }
    }

    fn new_p384(key: SecretKey<NistP384>) -> PrivateKey {
        PrivateKey {
            inner: Self::P384 {
                public: key.public_key().to_encoded_point(false),
                d: Zeroizing::new(key.to_bytes()),
                key,
            },
        }
    }

    fn new_secp256k1(key: SecretKey<Secp256k1>) -> PrivateKey {
        PrivateKey {
            inner: Self::Secp256k1 {
                public: key.public_key().to_encoded_point(false),
                d: Zeroizing::new(key.to_bytes()),
                key,
            },
        }
    }
}

#[derive(Clone)]
enum ErasedPublicKey {
    P256 {
        key: elliptic_curve::PublicKey<NistP256>,
        point: EncodedPoint<NistP256>,
    },
    P384 {
        key: elliptic_curve::PublicKey<NistP384>,
        point: EncodedPoint<NistP384>,
    },
    Secp256k1 {
        key: elliptic_curve::PublicKey<Secp256k1>,
        point: EncodedPoint<Secp256k1>,
    },
}

impl ErasedPublicKey {
    fn new_p256(key: elliptic_curve::PublicKey<NistP256>) -> PublicKey {
        PublicKey {
            inner: Self::P256 {
                key,
                point: key.to_encoded_point(false),
            },
        }
    }

    fn new_p384(key: elliptic_curve::PublicKey<NistP384>) -> PublicKey {
        PublicKey {
            inner: Self::P384 {
                key,
                point: key.to_encoded_point(false),
            },
        }
    }

    fn new_secp256k1(key: elliptic_curve::PublicKey<Secp256k1>) -> PublicKey {
        PublicKey {
            inner: Self::Secp256k1 {
                key,
                point: key.to_encoded_point(false),
            },
        }
    }
}

#[derive(Clone)]
pub(crate) enum ErasedSignature {
    P256(ecdsa::SignatureBytes<NistP256>),
    P384(ecdsa::SignatureBytes<NistP384>),
    Secp256k1(ecdsa::SignatureBytes<Secp256k1>),
}

impl From<ErasedSignature> for Vec<u8> {
    fn from(value: ErasedSignature) -> Self {
        match value {
            ErasedSignature::P256(sig) => sig.to_vec(),
            ErasedSignature::P384(sig) => sig.to_vec(),
            ErasedSignature::Secp256k1(sig) => sig.to_vec(),
        }
    }
}

impl AsRef<[u8]> for ErasedSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            ErasedSignature::P256(sig) => sig.as_ref(),
            ErasedSignature::P384(sig) => sig.as_ref(),
            ErasedSignature::Secp256k1(sig) => sig.as_ref(),
        }
    }
}

fn to_field_bytes<C: elliptic_curve::Curve>(
    bytes: &[u8],
) -> Result<&FieldBytes<C>, super::BackendError> {
    if bytes.len() != C::FieldBytesSize::USIZE {
        return Err(super::BackendError::InvalidEcPoint {
            expected: C::FieldBytesSize::USIZE,
            actual: bytes.len(),
        });
    }

    Ok(FieldBytes::<C>::from_slice(bytes))
}

/// A low level private EC key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    inner: ErasedPrivateKey,
}

impl ec::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = ErasedSignature;

    fn generate(alg: jwa::EcDSA) -> Result<Self> {
        let mut rng = OsRng;

        let key = match alg {
            EcDSA::Es256 => ErasedPrivateKey::new_p256(SecretKey::<NistP256>::random(&mut rng)),
            EcDSA::Es384 => ErasedPrivateKey::new_p384(SecretKey::<NistP384>::random(&mut rng)),
            EcDSA::Es512 => return Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => {
                ErasedPrivateKey::new_secp256k1(SecretKey::<Secp256k1>::random(&mut rng))
            }
        };

        Ok(key)
    }

    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        fn new_typed<C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic>(
            x: Vec<u8>,
            y: Vec<u8>,
            d: SecretSlice<u8>,
        ) -> Result<elliptic_curve::SecretKey<C>>
        where
            <C as elliptic_curve::Curve>::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
        {
            let x = to_field_bytes::<C>(&x)?;
            let y = to_field_bytes::<C>(&y)?;

            let d = d.expose_secret();
            let d = to_field_bytes::<C>(d)?;

            let point = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let secret = elliptic_curve::SecretKey::<C>::from_bytes(d)
                .map_err(super::BackendError::EllipticCurve)?;

            C::validate_public_key(&secret, &point).map_err(super::BackendError::EllipticCurve)?;

            Ok(secret)
        }

        Ok(match alg {
            EcDSA::Es256 => ErasedPrivateKey::new_p256(new_typed::<NistP256>(x, y, d)?),
            EcDSA::Es384 => ErasedPrivateKey::new_p384(new_typed::<NistP384>(x, y, d)?),
            EcDSA::Es512 => return Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => ErasedPrivateKey::new_secp256k1(new_typed::<Secp256k1>(x, y, d)?),
        })
    }

    fn private_material(&self) -> &[u8] {
        match self.inner {
            ErasedPrivateKey::P256 { ref d, .. } => d.as_slice(),
            ErasedPrivateKey::P384 { ref d, .. } => d.as_slice(),
            ErasedPrivateKey::Secp256k1 { ref d, .. } => d.as_slice(),
        }
    }

    #[inline]
    fn public_point(&self) -> (&[u8], &[u8]) {
        let identity_point = || &[0u8][..];

        match self.inner {
            ErasedPrivateKey::P256 { public: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
            ErasedPrivateKey::P384 { public: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
            ErasedPrivateKey::Secp256k1 { public: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
        }
    }

    fn to_public_key(&self) -> Self::PublicKey {
        match self.inner {
            ErasedPrivateKey::P256 { ref key, .. } => ErasedPublicKey::new_p256(key.public_key()),
            ErasedPrivateKey::P384 { ref key, .. } => ErasedPublicKey::new_p384(key.public_key()),
            ErasedPrivateKey::Secp256k1 { ref key, .. } => {
                ErasedPublicKey::new_secp256k1(key.public_key())
            }
        }
    }

    fn sign(&mut self, data: &[u8], deterministic: bool) -> Result<Self::Signature> {
        let sig = match self.inner {
            ErasedPrivateKey::P256 { ref key, .. } => {
                let key = ecdsa::SigningKey::<NistP256>::from(key);

                let sig = if deterministic {
                    key.sign_recoverable(data)
                        .map_err(super::BackendError::Ecdsa)?
                        .0
                } else {
                    key.try_sign_with_rng(&mut OsRng, data)
                        .map_err(super::BackendError::Ecdsa)?
                };

                ErasedSignature::P256(sig.to_bytes())
            }
            ErasedPrivateKey::P384 { ref key, .. } => {
                let key = ecdsa::SigningKey::<NistP384>::from(key);

                let sig = if deterministic {
                    key.sign_recoverable(data)
                        .map_err(super::BackendError::Ecdsa)?
                        .0
                } else {
                    key.try_sign_with_rng(&mut OsRng, data)
                        .map_err(super::BackendError::Ecdsa)?
                };

                ErasedSignature::P384(sig.to_bytes())
            }
            ErasedPrivateKey::Secp256k1 { ref key, .. } => {
                let key = ecdsa::SigningKey::<Secp256k1>::from(key);

                let sig = if deterministic {
                    key.sign_recoverable(data)
                        .map_err(super::BackendError::Ecdsa)?
                        .0
                } else {
                    key.try_sign_with_rng(&mut OsRng, data)
                        .map_err(super::BackendError::Ecdsa)?
                };

                ErasedSignature::Secp256k1(sig.to_bytes())
            }
        };

        Ok(sig)
    }
}

/// A low level public EC key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PublicKey {
    inner: ErasedPublicKey,
}

impl ec::PublicKey for PublicKey {
    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        fn new_typed<C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic>(
            x: Vec<u8>,
            y: Vec<u8>,
        ) -> Result<elliptic_curve::PublicKey<C>>
        where
            <C as elliptic_curve::Curve>::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
        {
            let x = to_field_bytes::<C>(&x)?;
            let y = to_field_bytes::<C>(&y)?;

            let point = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let key: Option<_> = elliptic_curve::PublicKey::<C>::from_encoded_point(&point).into();
            let key = key.ok_or(super::BackendError::InvalidEcKey)?;
            Ok(key)
        }

        Ok(match alg {
            EcDSA::Es256 => ErasedPublicKey::new_p256(new_typed::<NistP256>(x, y)?),
            EcDSA::Es384 => ErasedPublicKey::new_p384(new_typed::<NistP384>(x, y)?),
            EcDSA::Es512 => return Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => ErasedPublicKey::new_secp256k1(new_typed::<Secp256k1>(x, y)?),
        })
    }

    fn to_point(&self) -> (&[u8], &[u8]) {
        let identity_point = || &[0u8][..];

        match self.inner {
            ErasedPublicKey::P256 { point: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
            ErasedPublicKey::P384 { point: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
            ErasedPublicKey::Secp256k1 { point: ref p, .. } => (
                p.x().map(|a| a.as_slice()).unwrap_or_else(identity_point),
                p.y().map(|a| a.as_slice()).unwrap_or_else(identity_point),
            ),
        }
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(match self.inner {
            ErasedPublicKey::P256 { ref key, .. } => {
                let Ok(sig) = ecdsa::Signature::<NistP256>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<NistP256>::from(key);
                key.verify(msg, &sig).is_ok()
            }
            ErasedPublicKey::P384 { ref key, .. } => {
                let Ok(sig) = ecdsa::Signature::<NistP384>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<NistP384>::from(key);
                key.verify(msg, &sig).is_ok()
            }
            ErasedPublicKey::Secp256k1 { ref key, .. } => {
                let Ok(sig) = ecdsa::Signature::<Secp256k1>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<Secp256k1>::from(key);
                key.verify(msg, &sig).is_ok()
            }
        })
    }
}
