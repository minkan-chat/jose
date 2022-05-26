use super::{ec::EcPublic, okp::OkpPublic, rsa::RsaPublicKey};

/// The `public` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug)]
pub enum Public {
    /// The public part of a
    Rsa(RsaPublicKey),
    Ec(EcPublic),
    Okp(OkpPublic),
}
