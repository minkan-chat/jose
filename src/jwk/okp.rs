//! Key types for Curve25519 and Curve448 (`crv` parameter = `OKP`)

use self::{
    curve25519::{Curve25519Private, Curve25519Public},
    curve448::{Curve448Private, Curve448Public},
};

/// Curve25519 key types (EdDSA and ECDH)
pub mod curve25519 {
    /// EdDSA part of Curve25519
    pub mod ed25519 {
        /// An Ed25519 public key used to verify signatures
        #[derive(Debug)]
        pub struct Ed25519PublicKey;

        /// An Ed25519 private key used to create signatures
        #[derive(Debug)]
        pub struct Ed25519PrivateKey;
    }

    /// ECDH part of Curve25519
    pub mod x25519 {
        /// An ECDH public key
        #[derive(Debug)]
        pub struct X25519PublicKey;

        /// An ECDH private key
        #[derive(Debug)]
        pub struct X25519PrivateKey;
    }

    /// Either a public key for Ed25519 or X25519 (Diffie-Hellman)
    #[derive(Debug)]
    pub enum Curve25519Public {
        /// Public Ed25519 part
        Ed(ed25519::Ed25519PublicKey),
        /// Public X25519 part
        X(x25519::X25519PublicKey),
    }

    /// Either a private key for Ed25519 or X25519 (Diffie-Hellman)
    #[derive(Debug)]
    pub enum Curve25519Private {
        /// Private Ed25519 part
        Ed(ed25519::Ed25519PrivateKey),
        /// Private X25519 part
        X(x25519::X25519PrivateKey),
    }
}

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
#[derive(Debug)]
pub enum OkpPublic {
    /// `kty` is `OKP` and `crv` is either `Ed25519` or `X25519`
    Curve25519(Curve25519Public),
    /// `kty` is `OKP` and `crv` is either `Ed448` or `X448`
    Curve448(Curve448Public),
}

/// The private part of an `OKP` key type
#[non_exhaustive]
#[derive(Debug)]
pub enum OkpPrivate {
    /// `kty` is `OKP` and `crv` is either `Ed25519` or `X25519`
    Curve25519(Curve25519Private),
    /// `kty` is `OKP` and `crv` is either `Ed448` or `X448`
    Curve448(Curve448Private),
}
