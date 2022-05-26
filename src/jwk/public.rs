use super::{ec::EcPublic, okp::OkpPublic, rsa::RsaPublicKey};

/// The `public` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug)]
pub enum Public {
    /// The public part of a Rsa key
    Rsa(RsaPublicKey),
    /// The public part of an elliptic curve
    Ec(EcPublic),
    /// The public part of an `OKP` key type, probably the public part of a
    /// curve25519 or curve448 key
    Okp(OkpPublic),
}
