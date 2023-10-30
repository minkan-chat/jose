//! Key types for Curve-25519
mod ed25519;
mod x25519;

use serde::{Deserialize, Serialize};

pub use self::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signer, Ed25519Verifier};

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