//! Rsa key types

/// A public Rsa key used for signature verification and/or encryption
#[derive(Debug)]
pub struct RsaPublicKey(rsa::RsaPublicKey);

/// A private Rsa key used to create signatures and/or to decrypt
#[derive(Debug)]
pub struct RsaPrivateKey(rsa::RsaPrivateKey);
