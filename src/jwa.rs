//! Implementation of JSON Web Algorithms (JWA) as defined in [RFC 7518]
//!
//! [RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518>

mod aes_cbc_hs;
mod aes_gcm;
mod aes_kw;
mod ecdh_es;
mod ecdsa;
mod hmac;
mod pbes2;
mod rsaes_oaep;
mod rsassa_pkcs1_v1_5;
mod rsassa_pss;

#[doc(inline)]
pub use self::{
    aes_cbc_hs::AesCbcHs,
    aes_gcm::{AesGcm, AesGcmVariant},
    aes_kw::AesKw,
    ecdh_es::{EcDhES, EcDhESMode},
    ecdsa::EcDSA,
    hmac::Hmac,
    pbes2::{Pbes2, Pbes2Variant},
    rsaes_oaep::RsaesOaep,
    rsassa_pkcs1_v1_5::RsassaPkcs1V1_5,
    rsassa_pss::RsassaPss,
};

/// A JSON Web Algorithm (JWA) for singing operations (JWS) as defined in [RFC
/// 7518 section 3]
///
/// This enum covers the `alg` Header Parameter Values for JWS. It represents
/// the table from [section 3.1].
///
/// [RFC 7518 section 3]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3>
/// [section 3.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.1>
#[derive(Debug)]
pub enum JsonWebSigningAlgorithm {
    /// HMAC with SHA-2 Functions
    Hmac(Hmac),
    /// RSASSA-PKCS1-v1_5 using SHA-2 Functions
    RsassaPkcs1V1_5(RsassaPkcs1V1_5),
    /// Digital Signature with ECDSA
    EcDSA(EcDSA),
    /// Digital Signature with RSASSA-PSS
    RsassaPss(RsassaPss),
    /// The "none" algorithm as defined in [section 3.6 of RFC 7518]
    ///
    /// [section 3.6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.6>
    None,
}

/// A JSON Web Algorithm (JWA) for encryption and decryption of JWEs as defined
/// in [RFC 7518 section 4]
///
/// This enum covers the `alg` Header Parameter Values for JWE. It represents
/// the table from [section 4.1].
///
/// [RFC 7518 section 4]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4>
/// [section 4.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.1>
#[derive(Debug)]
pub enum JsonWebEncryptionAlgorithm {
    /// Key Encryption with RSAES-PKCS1-v1_5 as defined in [section 4.2]
    ///
    /// [section 4.2]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.2>
    Rsa1_5,
    /// Key Encryption with RSAES OAEP
    RsaesOaep(RsaesOaep),
    /// AES Key Wrap
    AesKw(AesKw),
    /// Direct use of a shared symmetric key as the CEK as defined in [section
    /// 4.5]
    ///
    /// [section 4.5]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.5>
    Direct,
    /// Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
    EcDhES(EcDhES),
    /// Key wrapping with AES GCM
    AesGcmKw(AesGcm),
    /// PBES2 Key Encryption
    Pbes2(Pbes2),
}

/// A JSON Web Algorithm (JWA) for content encryption and decryption of a JWE as
/// defined in [RFC 7518 section 5]
///
/// This enum covers the `enc` Header Parameter Values for JWE. It represents
/// the table from [section 5.1].
///
/// [RFC 7518 section 5]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5>
/// [section 5.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.1>
#[derive(Debug)]
pub enum JsonWebContentEncryptionAlgorithm {
    /// Content Encryption using AES in CBC mode with HMAC
    AesCbcHs(AesCbcHs),
    /// Content Encryption using AES GCM
    AesGcm(AesGcmVariant),
}
