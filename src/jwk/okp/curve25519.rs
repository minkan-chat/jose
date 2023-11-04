//! Key types for Curve-25519
mod ed25519;
mod x25519;

use alloc::string::String;

use serde::{Deserialize, Serialize};

pub use self::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signer, Ed25519Verifier};
use crate::jwk::Thumbprint;

/// Either a public key for Ed25519 or X25519 (Diffie-Hellman)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Curve25519Public {
    /// Public Ed25519 part
    Ed(Ed25519PublicKey),
    // /// Public X25519 part
    // X(X25519PublicKey),
}

impl crate::sealed::Sealed for Curve25519Public {}
impl Thumbprint for Curve25519Public {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Curve25519Public::Ed(key) => key.thumbprint_prehashed(),
        }
    }
}

/// Either a private key for Ed25519 or X25519 (Diffie-Hellman)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Curve25519Private {
    /// Private Ed25519 part
    Ed(Ed25519PrivateKey),
    // /// Private X25519 part
    // X(X25519PrivateKey),
}

impl crate::sealed::Sealed for Curve25519Private {}
impl Thumbprint for Curve25519Private {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Curve25519Private::Ed(key) => key.thumbprint_prehashed(),
        }
    }
}
