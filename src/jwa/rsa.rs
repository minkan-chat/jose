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
