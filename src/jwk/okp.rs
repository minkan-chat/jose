//! Key types for Curve25519 and Curve448 (`crv` parameter = `OKP`)

use self::curve25519::{Curve25519Private, Curve25519Public};

pub mod curve25519;

use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::Thumbprint;

/// TODO: unsupported, no implementation available
#[allow(missing_docs)]
pub mod curve448 {
    pub mod ed448 {

        #[derive(Debug)]
        pub struct Ed448Public;

        #[derive(Debug)]
        pub struct Ed448Private;
    }
    pub mod x448 {
        #[derive(Debug)]
        pub struct X448Public;
        #[derive(Debug)]
        pub struct X448Private;
    }

    #[derive(Debug)]
    pub enum Curve448Public {
        Ed(ed448::Ed448Public),
        X(x448::X448Public),
    }

    #[derive(Debug)]
    pub enum Curve448Private {
        Ed(ed448::Ed448Private),
        X(ed448::Ed448Private),
    }
}

/// The public part of an `OKP` key type
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]

pub enum OkpPublic {
    /// `kty` is `OKP` and `crv` is either `Ed25519` or `X25519`
    Curve25519(Curve25519Public),
    // /// `kty` is `OKP` and `crv` is either `Ed448` or `X448`
    // Curve448(Curve448Public),
}

impl crate::sealed::Sealed for OkpPublic {}
impl Thumbprint for OkpPublic {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            OkpPublic::Curve25519(key) => key.thumbprint_prehashed(),
        }
    }
}

/// The private part of an `OKP` key type
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OkpPrivate {
    /// `kty` is `OKP` and `crv` is either `Ed25519` or `X25519`
    Curve25519(Curve25519Private),
    // /// `kty` is `OKP` and `crv` is either `Ed448` or `X448`
    // Curve448(Curve448Private),
}

impl crate::sealed::Sealed for OkpPrivate {}
impl Thumbprint for OkpPrivate {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            OkpPrivate::Curve25519(key) => key.thumbprint_prehashed(),
        }
    }
}
