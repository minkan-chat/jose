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
mod rsa;

use serde::{Deserialize, Serialize};

#[doc(inline)]
pub use self::{
    aes_cbc_hs::AesCbcHs,
    aes_gcm::AesGcm,
    aes_kw::AesKw,
    ecdh_es::EcDhES,
    ecdsa::EcDSA,
    hmac::Hmac,
    pbes2::Pbes2,
    rsa::{RsaSigning, RsaesOaep, RsassaPkcs1V1_5, RsassaPss},
};

// FIXME: find better name for this enum
/// Either a JSON Web Algorithm for signing operations, or an algorithm for
/// encryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JsonWebAlgorithm {
    /// Signing algorithm.
    Signing(JsonWebSigningAlgorithm),
    /// Encryption algorithm.
    Encryption(JsonWebEncryptionAlgorithm),
}

/// A JSON Web Algorithm (JWA) for singing operations (JWS) as defined in [RFC
/// 7518 section 3]
///
/// This enum covers the `alg` Header Parameter Values for JWS. It represents
/// the table from [section 3.1].
///
/// [RFC 7518 section 3]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3>
/// [section 3.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.1>
// FIXME: `alg` header supports custom algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonWebSigningAlgorithm {
    /// HMAC with SHA-2 Functions
    Hmac(Hmac),
    /// RSASSA-PKCS1-v1_5 using SHA-2 Functions
    /// Digital Signature with RSASSA-PSS
    Rsa(RsaSigning),
    /// Digital Signature with ECDSA
    EcDSA(EcDSA),
    /// Digital Signature with Edwards-curve Digital Signature Algorithm (EdDSA)
    /// as defined in [section 3.1 of RFC 8037]
    ///
    /// Note: `EdDSA` should not be confused with
    /// [`EcDSA`](crate::jwa::JsonWebSigningAlgorithm::EcDSA).
    /// Also note that an EdDSA signature can either be made using `Ed25519` or
    /// `Ed448` but this information is not included.
    ///
    /// [section 3.1 of RFC 8037]: <https://datatracker.ietf.org/doc/html/rfc8037#section-3.1>
    EdDSA,
    /// The "none" algorithm as defined in [section 3.6 of RFC 7518].
    ///
    /// Using this algorithm essentially means that there is
    /// no integrity protection for the JWS.
    ///
    /// [section 3.6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.6>
    None,
}

// FIXME: move to extra file
macro_rules! impl_serde {
    ($T:ty, [
        $($name:literal => $val:expr; $valp:pat,)*
        err: $err:ident => $get_err:expr, $(,)?
    ]) => {
        impl<'de> Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let name = <&str as serde::Deserialize>::deserialize(deserializer)?;

                Ok(match name {
                    $($name => $val,)*
                    $err => return Err(<D::Error as serde::de::Error>::custom($get_err)),
                })
            }
        }

        impl Serialize for $T {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let name = match self {
                    $($valp => $name,)*
                };
                <&str as serde::Serialize>::serialize(&name, serializer)
            }
        }

    };
}

// don't judge this macro please.
// its ugly but it works
impl_serde!(
    JsonWebSigningAlgorithm,
    [
        "HS256" => Self::Hmac(Hmac::Hs256); Self::Hmac(Hmac::Hs256),
        "HS384" => Self::Hmac(Hmac::Hs384); Self::Hmac(Hmac::Hs384),
        "HS512" => Self::Hmac(Hmac::Hs512); Self::Hmac(Hmac::Hs512),

        "RS256" => Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs256)); Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs256)),
        "RS384" => Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs384)); Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs384)),
        "RS512" => Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs512)); Self::Rsa(RsaSigning::RsPkcs1V1_5(RsassaPkcs1V1_5::Rs512)),

        "ES256" => Self::EcDSA(EcDSA::Es256); Self::EcDSA(EcDSA::Es256),
        "ES384" => Self::EcDSA(EcDSA::Es384); Self::EcDSA(EcDSA::Es384),
        "ES512" => Self::EcDSA(EcDSA::Es512); Self::EcDSA(EcDSA::Es512),

        "EdDSA" => Self::EdDSA; Self::EdDSA,

        "PS256" => Self::Rsa(RsaSigning::Pss(RsassaPss::Ps256)); Self::Rsa(RsaSigning::Pss(RsassaPss::Ps256)),
        "PS384" => Self::Rsa(RsaSigning::Pss(RsassaPss::Ps384)); Self::Rsa(RsaSigning::Pss(RsassaPss::Ps384)),
        "PS512" => Self::Rsa(RsaSigning::Pss(RsassaPss::Ps512)); Self::Rsa(RsaSigning::Pss(RsassaPss::Ps512)),


        "none" => Self::None; Self::None,

        err: name => alloc::format!("invalid JSON Web Signing Algorithm: {}", name),
    ]
);

/// A JSON Web Algorithm (JWA) for encryption and decryption of Content
/// Encryption Key (CEK) as defined in [RFC 7518 section 4]
///
/// This enum covers the `alg` Header Parameter Values for JWE. It represents
/// the table from [section 4.1].
///
/// [RFC 7518 section 4]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4>
/// [section 4.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.1>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
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

impl_serde!(
    JsonWebEncryptionAlgorithm,
    [
        "RSA1_5" => Self::Rsa1_5; Self::Rsa1_5,
        "RSA-OAEP" => Self::RsaesOaep(RsaesOaep::RsaesOaep); Self::RsaesOaep(RsaesOaep::RsaesOaep),
        "RSA-OAEP-256" => Self::RsaesOaep(RsaesOaep::RsaesOaep256); Self::RsaesOaep(RsaesOaep::RsaesOaep256),
        "A128KW" => Self::AesKw(AesKw::Aes128); Self::AesKw(AesKw::Aes128),
        "A192KW" => Self::AesKw(AesKw::Aes192); Self::AesKw(AesKw::Aes192),
        "A256KW" => Self::AesKw(AesKw::Aes256); Self::AesKw(AesKw::Aes256),
        "dir" => Self::Direct; Self::Direct,
        "ECDH-ES" => Self::EcDhES(EcDhES::Direct); Self::EcDhES(EcDhES::Direct),
        "ECDH-ES+A128KW" => Self::EcDhES(EcDhES::AesKw(AesKw::Aes128)); Self::EcDhES(EcDhES::AesKw(AesKw::Aes128)),
        "ECDH-ES+A192KW" => Self::EcDhES(EcDhES::AesKw(AesKw::Aes192)); Self::EcDhES(EcDhES::AesKw(AesKw::Aes192)),
        "ECDH-ES+A256KW" => Self::EcDhES(EcDhES::AesKw(AesKw::Aes256)); Self::EcDhES(EcDhES::AesKw(AesKw::Aes256)),
        "A128GCMKW" => Self::AesGcmKw(AesGcm::Aes128); Self::AesGcmKw(AesGcm::Aes128),
        "A192GCMKW" => Self::AesGcmKw(AesGcm::Aes192); Self::AesGcmKw(AesGcm::Aes192),
        "A256GCMKW" => Self::AesGcmKw(AesGcm::Aes256); Self::AesGcmKw(AesGcm::Aes256),
        "PBES2-HS256+A128KW" => Self::Pbes2(Pbes2::Hs256Aes128); Self::Pbes2(Pbes2::Hs256Aes128),
        "PBES2-HS384+A192KW" => Self::Pbes2(Pbes2::Hs384Aes192); Self::Pbes2(Pbes2::Hs384Aes192),
        "PBES2-HS512+A256KW" => Self::Pbes2(Pbes2::Hs512Aes256); Self::Pbes2(Pbes2::Hs512Aes256),

        err: name => alloc::format!("invalid JSON Web Encryption Algorithm: {}", name),
    ]
);

/// A JSON Web Algorithm (JWA) for content encryption and decryption of a JWE as
/// defined in [RFC 7518 section 5]
///
/// This enum covers the `enc` Header Parameter Values for JWE. It represents
/// the table from [section 5.1].
///
/// [RFC 7518 section 5]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5>
/// [section 5.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-5.1>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonWebContentEncryptionAlgorithm {
    /// Content Encryption using AES in CBC mode with HMAC
    AesCbcHs(AesCbcHs),
    /// Content Encryption using AES GCM
    AesGcm(AesGcm),
}

impl_serde!(
    JsonWebContentEncryptionAlgorithm,
    [
        "A128CBC-HS256" => Self::AesCbcHs(AesCbcHs::Aes128CbcHs256); Self::AesCbcHs(AesCbcHs::Aes128CbcHs256),
        "A192CBC-HS384" => Self::AesCbcHs(AesCbcHs::Aes192CbcHs384); Self::AesCbcHs(AesCbcHs::Aes192CbcHs384),
        "A256CBC-HS512" => Self::AesCbcHs(AesCbcHs::Aes256CbcHs512); Self::AesCbcHs(AesCbcHs::Aes256CbcHs512),

        "A128GCM" => Self::AesGcm(AesGcm::Aes128); Self::AesGcm(AesGcm::Aes128),
        "A192GCM" => Self::AesGcm(AesGcm::Aes192); Self::AesGcm(AesGcm::Aes192),
        "A256GCM" => Self::AesGcm(AesGcm::Aes256); Self::AesGcm(AesGcm::Aes256),

        err: name => alloc::format!("invalid JSON Web Content Encryption Algorithm: {}", name),
    ]
);
