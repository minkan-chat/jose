use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{ec::EcPublic, okp::OkpPublic, Thumbprint};
use crate::crypto::rsa;

/// The `public` part of some asymmetric cryptographic key
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum Public {
    /// The public part of a Rsa key
    Rsa(rsa::PublicKey),
    /// The public part of an elliptic curve
    Ec(EcPublic),
    /// The public part of an `OKP` key type, probably the public part of a
    /// curve25519 or curve448 key
    Okp(OkpPublic),
}

impl crate::sealed::Sealed for Public {}
impl Thumbprint for Public {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Public::Rsa(key) => key.thumbprint_prehashed(),
            Public::Ec(key) => key.thumbprint_prehashed(),
            Public::Okp(key) => key.thumbprint_prehashed(),
        }
    }
}
