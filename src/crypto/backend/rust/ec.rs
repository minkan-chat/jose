use alloc::vec::Vec;

use ecdsa::EncodedPoint;
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint, ValidatePublicKey as _},
    FieldBytes, FieldBytesSize, SecretKey,
};
use generic_array::typenum::Unsigned as _;
use k256::Secp256k1;
use p256::NistP256;
use p384::NistP384;
use rand_core::OsRng;
use signature::Verifier as _;

use crate::{
    crypto::{backend::interface::ec, Result},
    jwa::{self, EcDSA},
};

#[derive(Clone)]
enum ErasedPrivateKey {
    P256(SecretKey<NistP256>),
    P384(SecretKey<NistP384>),
    Secp256k1(SecretKey<Secp256k1>),
}

#[derive(Clone)]
enum ErasedPublicKey {
    P256(elliptic_curve::PublicKey<NistP256>),
    P384(elliptic_curve::PublicKey<NistP384>),
    Secp256k1(elliptic_curve::PublicKey<Secp256k1>),
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
    bytes: Vec<u8>,
) -> Result<FieldBytes<C>, super::BackendError> {
    let len = bytes.len();

    FieldBytes::<C>::from_exact_iter(bytes).ok_or(super::BackendError::InvalidEcPoint {
        expected: FieldBytesSize::<C>::USIZE,
        actual: len,
    })
}

/// A low level private EC key.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct PrivateKey {
    inner: ErasedPrivateKey,
}

impl ec::PrivateKey for PrivateKey {
    type PrivateKeyMaterial = Vec<u8>;
    type PublicKey = PublicKey;
    type Signature = ErasedSignature;

    fn generate(alg: jwa::EcDSA) -> Result<Self> {
        let mut rng = OsRng;

        let key = match alg {
            EcDSA::Es256 => ErasedPrivateKey::P256(SecretKey::<NistP256>::random(&mut rng)),
            EcDSA::Es384 => ErasedPrivateKey::P384(SecretKey::<NistP384>::random(&mut rng)),
            EcDSA::Es512 => return Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => ErasedPrivateKey::Secp256k1(SecretKey::<Secp256k1>::random(&mut rng)),
        };
        Ok(Self { inner: key })
    }

    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>, d: Vec<u8>) -> Result<Self> {
        fn new_typed<C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic>(
            x: Vec<u8>,
            y: Vec<u8>,
            d: Vec<u8>,
        ) -> Result<elliptic_curve::SecretKey<C>>
        where
            <C as elliptic_curve::Curve>::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
            <C as elliptic_curve::CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
        {
            let x = to_field_bytes::<C>(x)?;
            let y = to_field_bytes::<C>(y)?;
            let d = to_field_bytes::<C>(d)?;

            let point = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);
            let secret = elliptic_curve::SecretKey::<C>::from_bytes(&d)
                .map_err(super::BackendError::EllipticCurve)?;

            C::validate_public_key(&secret, &point).map_err(super::BackendError::EllipticCurve)?;

            Ok(secret)
        }

        match alg {
            EcDSA::Es256 => Ok(Self {
                inner: ErasedPrivateKey::P256(new_typed::<NistP256>(x, y, d)?),
            }),
            EcDSA::Es384 => Ok(Self {
                inner: ErasedPrivateKey::P384(new_typed::<NistP384>(x, y, d)?),
            }),
            EcDSA::Es512 => Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => Ok(Self {
                inner: ErasedPrivateKey::Secp256k1(new_typed::<Secp256k1>(x, y, d)?),
            }),
        }
    }

    fn private_material(&self) -> Self::PrivateKeyMaterial {
        match self.inner {
            ErasedPrivateKey::P256(ref key) => key.to_bytes().to_vec(),
            ErasedPrivateKey::P384(ref key) => key.to_bytes().to_vec(),
            ErasedPrivateKey::Secp256k1(ref key) => key.to_bytes().to_vec(),
        }
    }

    #[inline]
    fn public_point(
        &self,
    ) -> (
        <Self::PublicKey as ec::PublicKey>::Coordinate,
        <Self::PublicKey as ec::PublicKey>::Coordinate,
    ) {
        ec::PublicKey::to_point(&self.to_public_key())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        match self.inner {
            ErasedPrivateKey::P256(ref key) => PublicKey {
                inner: ErasedPublicKey::P256(key.public_key()),
            },
            ErasedPrivateKey::P384(ref key) => PublicKey {
                inner: ErasedPublicKey::P384(key.public_key()),
            },
            ErasedPrivateKey::Secp256k1(ref key) => PublicKey {
                inner: ErasedPublicKey::Secp256k1(key.public_key()),
            },
        }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature> {
        let sig = match self.inner {
            ErasedPrivateKey::P256(ref key) => {
                let key = ecdsa::SigningKey::<NistP256>::from(key);
                let (sig, _) = key
                    .sign_recoverable(data)
                    .map_err(super::BackendError::Ecdsa)?;
                ErasedSignature::P256(sig.to_bytes())
            }
            ErasedPrivateKey::P384(ref key) => {
                let key = ecdsa::SigningKey::<NistP384>::from(key);
                let (sig, _) = key
                    .sign_recoverable(data)
                    .map_err(super::BackendError::Ecdsa)?;
                ErasedSignature::P384(sig.to_bytes())
            }
            ErasedPrivateKey::Secp256k1(ref key) => {
                let key = ecdsa::SigningKey::<Secp256k1>::from(key);
                let (sig, _) = key
                    .sign_recoverable(data)
                    .map_err(super::BackendError::Ecdsa)?;
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
    type Coordinate = Vec<u8>;

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
            let x = to_field_bytes::<C>(x)?;
            let y = to_field_bytes::<C>(y)?;

            let point = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);
            let key: Option<_> = elliptic_curve::PublicKey::<C>::from_encoded_point(&point).into();
            let key = key.ok_or(super::BackendError::InvalidEcKey)?;
            Ok(key)
        }

        match alg {
            EcDSA::Es256 => Ok(Self {
                inner: ErasedPublicKey::P256(new_typed::<NistP256>(x, y)?),
            }),
            EcDSA::Es384 => Ok(Self {
                inner: ErasedPublicKey::P384(new_typed::<NistP384>(x, y)?),
            }),
            EcDSA::Es512 => Err(super::BackendError::CurveNotSupported("P-521").into()),
            EcDSA::Es256K => Ok(Self {
                inner: ErasedPublicKey::Secp256k1(new_typed::<Secp256k1>(x, y)?),
            }),
        }
    }

    fn to_point(&self) -> (Self::Coordinate, Self::Coordinate) {
        let identity_point = || alloc::vec![0u8];
        match self.inner {
            ErasedPublicKey::P256(ref key) => {
                let point = key.to_encoded_point(false);
                (
                    point.x().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                    point.y().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                )
            }
            ErasedPublicKey::P384(ref key) => {
                let point = key.to_encoded_point(false);
                (
                    point.x().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                    point.y().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                )
            }
            ErasedPublicKey::Secp256k1(ref key) => {
                let point = key.to_encoded_point(false);
                (
                    point.x().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                    point.y().map(|a| a.to_vec()).unwrap_or_else(identity_point),
                )
            }
        }
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(match self.inner {
            ErasedPublicKey::P256(ref key) => {
                let Ok(sig) = ecdsa::Signature::<NistP256>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<NistP256>::from(key);
                key.verify(msg, &sig).is_ok()
            }
            ErasedPublicKey::P384(ref key) => {
                let Ok(sig) = ecdsa::Signature::<NistP384>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<NistP384>::from(key);
                key.verify(msg, &sig).is_ok()
            }
            ErasedPublicKey::Secp256k1(ref key) => {
                let Ok(sig) = ecdsa::Signature::<Secp256k1>::try_from(signature) else {
                    return Ok(false);
                };
                let key = ecdsa::VerifyingKey::<Secp256k1>::from(key);
                key.verify(msg, &sig).is_ok()
            }
        })
    }
}
