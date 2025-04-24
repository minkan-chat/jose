//! This backend is a dummy backend, that will return an error for all
//! methods.
//!
//! This is only used for testing purposes, to make the code compile.

use alloc::vec::Vec;

use super::interface;
use crate::crypto::Result;

#[derive(Debug, thiserror::Error)]
#[error("the dummy crypto backend does not support any operations")]
pub(crate) struct Error;

/// The dummy backend.
#[derive(Debug)]
pub(crate) enum Backend {}

impl interface::Backend for Backend {
    type EcPrivateKey = DummyKey;
    type EcPublicKey = DummyKey;
    type EdPrivateKey = DummyKey;
    type EdPublicKey = DummyKey;
    type Error = Error;
    type HmacKey = DummyKey;
    type RsaPrivateKey = DummyKey;
    type RsaPublicKey = DummyKey;

    fn fill_random(_buf: &mut [u8]) -> Result<(), Self::Error> {
        Err(Error)
    }

    fn sha256(_: &[u8]) -> Vec<u8> {
        panic!("The dummy backend does not support any operations");
    }

    fn sha384(_: &[u8]) -> Vec<u8> {
        panic!("The dummy backend does not support any operations");
    }

    fn sha512(_: &[u8]) -> Vec<u8> {
        panic!("The dummy backend does not support any operations");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DummyKey {
    _private: (),
}

impl interface::ec::PrivateKey for DummyKey {
    type PrivateKeyMaterial = Vec<u8>;
    type PublicKey = DummyKey;
    type Signature = Vec<u8>;

    fn new(_alg: crate::jwa::EcDSA, _x: Vec<u8>, _y: Vec<u8>, _d: Vec<u8>) -> Result<Self> {
        Err(Error.into())
    }

    fn generate(_: crate::jwa::EcDSA) -> Result<Self> {
        Err(Error.into())
    }

    fn private_material(&self) -> Self::PrivateKeyMaterial {
        unreachable!()
    }

    fn public_point(
        &self,
    ) -> (
        <Self::PublicKey as interface::ec::PublicKey>::Coordinate,
        <Self::PublicKey as interface::ec::PublicKey>::Coordinate,
    ) {
        unreachable!()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        unreachable!()
    }

    fn sign(&mut self, _: &[u8]) -> Result<Self::Signature> {
        unreachable!()
    }
}

impl interface::ec::PublicKey for DummyKey {
    type Coordinate = Vec<u8>;

    fn new(_: crate::jwa::EcDSA, _: Vec<u8>, _: Vec<u8>) -> Result<Self> {
        Err(Error.into())
    }

    fn to_point(&self) -> (Self::Coordinate, Self::Coordinate) {
        unreachable!()
    }

    fn verify(&mut self, _: &[u8], _: &[u8]) -> Result<bool> {
        unreachable!()
    }
}

impl interface::okp::PrivateKey for DummyKey {
    type PublicKey = DummyKey;
    type Signature = Vec<u8>;

    fn generate(_: interface::okp::CurveAlgorithm) -> Result<Self> {
        Err(Error.into())
    }

    fn new(_: interface::okp::CurveAlgorithm, _: Vec<u8>, _: Vec<u8>) -> Result<Self> {
        Err(Error.into())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        unreachable!()
    }

    fn to_bytes(&self) -> Vec<u8> {
        unreachable!()
    }

    fn sign(&mut self, _: &[u8]) -> Result<Self::Signature> {
        unreachable!()
    }
}

impl interface::okp::PublicKey for DummyKey {
    fn new(_: interface::okp::CurveAlgorithm, _: Vec<u8>) -> Result<Self> {
        Err(Error.into())
    }

    fn to_bytes(&self) -> Vec<u8> {
        unreachable!()
    }

    fn verify(&mut self, _: &[u8], _: &[u8]) -> Result<bool> {
        unreachable!()
    }
}

impl interface::hmac::Key for DummyKey {
    type Signature = Vec<u8>;

    fn new(_: crate::jwa::Hmac, _: &[u8]) -> Result<Self> {
        Err(Error.into())
    }

    fn sign(&mut self, _: &[u8]) -> Result<Self::Signature> {
        unreachable!()
    }
}

impl interface::rsa::PrivateKey for DummyKey {
    type BigInt = DummyKey;
    type PublicKey = DummyKey;
    type Signature = Vec<u8>;

    fn from_components(_: interface::rsa::PrivateKeyComponents) -> Result<Self> {
        Err(Error.into())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        unreachable!()
    }

    fn primes(&self) -> Vec<Self::BigInt> {
        unreachable!()
    }

    fn n(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn e(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn d(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn dp(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn dq(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn qi(&self) -> Self::BigInt {
        unreachable!()
    }

    fn sign(&mut self, _: crate::jwa::RsaSigning, _: &[u8]) -> Result<Self::Signature> {
        unreachable!()
    }
}

impl interface::rsa::PublicKey for DummyKey {
    type BigInt = DummyKey;

    fn from_components(_: interface::rsa::PublicKeyComponents) -> Result<Self> {
        Err(Error.into())
    }

    fn n(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn e(&self) -> &<Self::BigInt as interface::rsa::BigInt>::Ref {
        unreachable!()
    }

    fn verify(
        &mut self,
        _alg: crate::jwa::RsaSigning,
        _msg: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        unreachable!()
    }
}

impl interface::rsa::BigInt for DummyKey {
    type Ref = DummyKey;
}

impl interface::rsa::BigIntRef for DummyKey {
    fn to_bytes_be(&self) -> Vec<u8> {
        unreachable!()
    }
}
