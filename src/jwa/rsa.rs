mod rsaes_oaep;
mod rsassa_pkcs1_v1_5;
mod rsassa_pss;

pub use self::{rsaes_oaep::RsaesOaep, rsassa_pkcs1_v1_5::RsassaPkcs1V1_5, rsassa_pss::RsassaPss};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaSigning {
    Pss(RsassaPss),
    RsPkcs1V1_5(RsassaPkcs1V1_5),
}
