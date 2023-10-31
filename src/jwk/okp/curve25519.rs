//! Key types for Curve-25519
mod ed25519;
mod x25519;

pub use ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signer, Ed25519Verifier};
use serde::{Deserialize, Serialize};

/// Either a public key for Ed25519 or X25519 (Diffie-Hellman)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Curve25519Public {
    /// Public Ed25519 part
    Ed(Ed25519PublicKey),
    // /// Public X25519 part
    // X(X25519PublicKey),
}

/// Either a private key for Ed25519 or X25519 (Diffie-Hellman)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Curve25519Private {
    /// Private Ed25519 part
    Ed(Ed25519PrivateKey),
    // /// Private X25519 part
    // X(X25519PrivateKey),
}
