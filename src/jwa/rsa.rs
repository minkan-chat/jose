mod rsaes_oaep;
mod rsassa_pkcs1_v1_5;
mod rsassa_pss;

pub use self::{rsaes_oaep::RsaesOaep, rsassa_pkcs1_v1_5::RsassaPkcs1V1_5, rsassa_pss::RsassaPss};

/// Some signing algorithm using a RSA key under the hood
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsaSigning {
    /// Digital Signature with RSASSA-PSS
    Pss(RsassaPss),
    /// Digital Signature with RSASSA-PKCS1-v1_5
    RsPkcs1V1_5(RsassaPkcs1V1_5),
}

impl From<RsaSigning> for super::JsonWebAlgorithm {
    fn from(x: RsaSigning) -> Self {
        Self::Signing(super::JsonWebSigningAlgorithm::Rsa(x))
    }
}

impl From<RsaSigning> for super::JsonWebSigningAlgorithm {
    fn from(x: RsaSigning) -> Self {
        Self::Rsa(x)
    }
}

impl From<RsassaPss> for RsaSigning {
    fn from(x: RsassaPss) -> Self {
        RsaSigning::Pss(x)
    }
}

impl From<RsassaPss> for super::JsonWebSigningAlgorithm {
    fn from(x: RsassaPss) -> Self {
        Self::Rsa(RsaSigning::Pss(x))
    }
}

impl From<RsassaPss> for super::JsonWebAlgorithm {
    fn from(x: RsassaPss) -> Self {
        Self::Signing(super::JsonWebSigningAlgorithm::Rsa(RsaSigning::Pss(x)))
    }
}

impl From<RsassaPkcs1V1_5> for RsaSigning {
    fn from(x: RsassaPkcs1V1_5) -> Self {
        RsaSigning::RsPkcs1V1_5(x)
    }
}

impl From<RsassaPkcs1V1_5> for super::JsonWebSigningAlgorithm {
    fn from(x: RsassaPkcs1V1_5) -> Self {
        Self::Rsa(RsaSigning::RsPkcs1V1_5(x))
    }
}

impl From<RsassaPkcs1V1_5> for super::JsonWebAlgorithm {
    fn from(x: RsassaPkcs1V1_5) -> Self {
        Self::Signing(super::JsonWebSigningAlgorithm::Rsa(
            RsaSigning::RsPkcs1V1_5(x),
        ))
    }
}
