use super::{ec::EcPrivate, okp::OkpPrivate, rsa::RsaPrivateKey};

#[non_exhaustive]
#[derive(Debug)]
pub enum Private {
    Rsa(RsaPrivateKey),
    Ec(EcPrivate),
    Okp(OkpPrivate),
}
