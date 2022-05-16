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

// FIXME: find better name for this enum
pub enum JsonWebSigningOrEnncryptionAlgorithm {
    Signing(JsonWebSigningAlgorithm),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonWebSigningAlgorithm {
    /// HMAC with SHA-2 Functions
    Hmac(Hmac),
    /// RSASSA-PKCS1-v1_5 using SHA-2 Functions
    RsassaPkcs1V1_5(RsassaPkcs1V1_5),
    /// Digital Signature with ECDSA
    EcDSA(EcDSA),
    /// Digital Signature with RSASSA-PSS
    RsassaPss(RsassaPss),
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
        $($name:literal => $val:tt::$val2:tt $(($i_val:path))?,)*
        err: $err:ident => $get_err:expr, $(,)?
    ]) => {
        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let name = <&str as serde::Deserialize>::deserialize(deserializer)?;

                Ok(match name {
                    $($name => $val::$val2$(($i_val))?,)*
                    $err => return Err(<D::Error as serde::de::Error>::custom($get_err)),
                })
            }
        }

        impl serde::Serialize for JsonWebSigningAlgorithm {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let name = match self {
                    $($val::$val2$(($i_val))? => $name,)*
                };
                <&str as serde::Serialize>::serialize(&name, serializer)
            }
        }

    };
}

impl_serde!(
    JsonWebSigningAlgorithm,
    [
        "HS256" => Self::Hmac(Hmac::Hs256),
        "HS384" => Self::Hmac(Hmac::Hs384),
        "HS512" => Self::Hmac(Hmac::Hs512),

        "RS256" => Self::RsassaPkcs1V1_5(RsassaPkcs1V1_5::Rs256),
        "RS384" => Self::RsassaPkcs1V1_5(RsassaPkcs1V1_5::Rs384),
        "RS512" => Self::RsassaPkcs1V1_5(RsassaPkcs1V1_5::Rs512),

        "ES256" => Self::EcDSA(EcDSA::Es256),
        "ES384" => Self::EcDSA(EcDSA::Es384),
        "ES512" => Self::EcDSA(EcDSA::Es512),

        "PS256" => Self::RsassaPss(RsassaPss::Ps256),
        "PS384" => Self::RsassaPss(RsassaPss::Ps384),
        "PS512" => Self::RsassaPss(RsassaPss::Ps512),

        "none" => Self::None,

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonWebContentEncryptionAlgorithm {
    /// Content Encryption using AES in CBC mode with HMAC
    AesCbcHs(AesCbcHs),
    /// Content Encryption using AES GCM
    AesGcm(AesGcmVariant),
}
