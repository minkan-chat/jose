//! Key types for Curve25519 and Curve448 (`crv` parameter = `OKP`)

use self::curve25519::{Curve25519Private, Curve25519Public};

pub mod curve25519;

use serde::{Deserialize, Serialize};

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
