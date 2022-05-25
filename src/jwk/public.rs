use super::{ec::EcPublic, okp::OkpPublic, rsa::RsaPrivateKey};

#[non_exhaustive]
#[derive(Debug)]
pub enum Public {
    Rsa(RsaPrivateKey),
    Ec(EcPublic),
    Okp(OkpPublic),
}
