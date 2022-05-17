use alloc::{boxed::Box, string::String, vec::Vec};
use core::hash::BuildHasher;

use hashbrown::{hash_map::DefaultHashBuilder, HashSet};

pub mod ec;
pub mod rsa;

use self::{ec::EllipticCurveKey, rsa::RsaKey};
use crate::jwa::JsonWebSigningOrEnncryptionAlgorithm;

/// <https://datatracker.ietf.org/doc/html/rfc7517>
///
/// # Warning
///
/// If you use a custom [`Hasher`](core::hash::Hasher), make sure to have a true
/// source of randomness to avoid [hash collision attacks][1].
///
/// [1]: <https://en.wikipedia.org/wiki/Collision_attack>
#[derive(Debug)]
pub struct JsonWebKey<S = DefaultHashBuilder>
where
    S: BuildHasher + Sync,
{
    /// `kty` parameter section 4.1
    // this should also cover the `alg` header or try to guess it
    key_type: JsonWebKeyType,
    /// `key_ops` parameter section 4.3
    key_operations: Option<HashSet<KeyOperations, S>>,
    // this is replaced by the new JsonWebKeyType
    /// `alg` parameter section 4.4
    // the spec says this member is OPTIONAL but I think it should not appear
    // as Option<_> in our public api since we have to decide what algorithm
    // to use at some point (en/decryption, signing/verification) anyway.
    // FIXME: consider removing this since it could be handled by `kty`
    algorithm: Option<JsonWebSigningOrEnncryptionAlgorithm>,
    /// `kid` parameter section 4.4
    // FIXME: Consider an enum if this value is a valid JWK Thumbprint,
    // see <https://www.rfc-editor.org/rfc/rfc7638>
    kid: Option<String>,
    /// `x5u` parameter section 4.6
    // FIXME: consider using an dedicated URL type for this and ensure the protocol
    // uses TLS or some other form of integrity protection.
    // There are other things to consider, see the relevant section in the RFC.
    x509_url: Option<String>,
    /// `x5c` parameter section 4.7
    // just look at the rfc
    x509_certificate_chain: Option<String>,
    /// `x5t` parameter section 4.8
    // FIXME: sha1 is vulnerable against collision attacks and should not be used
    // If we accept this parameter, consider using the `sha1collisiondetection` crate
    // also consider using a fixed size array instead of a String since the output of these hash
    // functions has a fixed width
    x509_certificate_sha1_thumbprint: Option<String>,
    /// `x5t#S256` parameter section 4.9
    x509_certificate_sha256_thumbprint: Option<String>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum KeyUsage {
    Signing,
    Encryption,
    Other(String),
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum KeyOperations {
    Sign,
    Verify,
    Encrypt,
    Decrpy,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
    Other(String),
}

/// A [`JsonWebKey`](crate::jwk::JsonWebKey) represents a cryptographic key. It
/// can either be symmetric or asymmetric. In the latter case, it can store
/// public or private information about the key. This enum represents the key
/// types as defined in [RFC 7518 section 6].
///
/// [RFC 7518 section 6]: <https://datatracker.ietf.org/doc/html/rfc7518#section-6>
#[derive(Debug)]
pub enum JsonWebKeyType {
    ///
    Symmetric(SymmetricJsonWebKey),
    ///
    Asymmetric(Box<AsymmetricJsonWebKey>),
}

#[derive(Debug)]
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
pub enum SymmetricJsonWebKey {
    OctetSequence {
        /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
        k: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum AsymmetricJsonWebKey {
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.2>
    EllipticCurve(EllipticCurveKey),
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.3>
    Rsa(RsaKey),
}
