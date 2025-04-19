use alloc::{borrow::Cow, boxed::Box, format, string::String};
use core::convert::Infallible;

use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{de::Error, Deserialize, Serialize};
use signature::Signer as _;

const CRV: &str = "Ed25519";
const KTY: &str = "OKP";

use super::{Curve25519Private, Curve25519Public};
use crate::{
    base64_url::Base64UrlBytes,
    crypto,
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::{
        okp::{OkpPrivate, OkpPublic},
        AsymmetricJsonWebKey, FromKey, IntoJsonWebKey, JsonWebKeyType, Private, Public, Thumbprint,
    },
    jws::{InvalidSigningAlgorithmError, Signer, Verifier, VerifyError},
    sealed::Sealed,
    JsonWebKey,
};
/// An Ed25519 public key used to verify signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Thumbprint for Ed25519PublicKey {
    fn thumbprint_prehashed(&self) -> String {
        crate::jwk::thumbprint::serialize_key_thumbprint(self)
    }
}

/// An Ed25519 private key used to create signatures
#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey(SigningKey);

impl Thumbprint for Ed25519PrivateKey {
    fn thumbprint_prehashed(&self) -> String {
        crate::jwk::thumbprint::serialize_key_thumbprint(self)
    }
}

impl Ed25519PrivateKey {
    /// Generate a new private key using the provided rng
    pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Get the public key corresponding to this private key.
    pub fn to_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
    }
}

/// A [`Signer`] using a [`Ed25519PrivateKey`]
#[derive(Debug)]
pub struct Ed25519Signer(SigningKey);

impl FromKey<Ed25519PrivateKey> for Ed25519Signer {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(value: Ed25519PrivateKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        if !matches!(
            alg,
            JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::EdDSA)
        ) {
            return Err(InvalidSigningAlgorithmError);
        }
        Ok(Self(value.0))
    }
}

impl Signer<[u8; Signature::BYTE_SIZE]> for Ed25519Signer {
    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        JsonWebSigningAlgorithm::EdDSA
    }

    fn sign(&mut self, msg: &[u8]) -> Result<[u8; Signature::BYTE_SIZE], crypto::Error> {
        self.0
            .try_sign(msg)
            .map(|v| v.to_bytes())
            .map_err(|_| todo!())
    }
}

/// A [`Verifier`] using a [`Ed25519PublicKey`]
#[derive(Debug)]
pub struct Ed25519Verifier(VerifyingKey);

impl Verifier for Ed25519Verifier {
    /// Verify a signature created by an [`Ed25519Signer`]
    ///
    /// Note
    ///
    /// The verification is strict and rejects some public keys depending on
    /// their encoding. Internally, this uses [`verify_strict`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).
    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        // FIXME: this needs interop testing in case this is handled differently by
        // other implementations
        // See <https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html#on-the-multiple-sources-of-malleability-in-ed25519-signatures>
        self.0
            .verify_strict(
                msg,
                &Signature::from_slice(signature).map_err(|_| VerifyError::InvalidSignature)?,
            )
            .map_err(|_| VerifyError::InvalidSignature)
    }
}

impl FromKey<Ed25519PublicKey> for Ed25519Verifier {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(key: Ed25519PublicKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::EdDSA) => Ok(Self(key.0)),
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

/// Create a [`Verifier`] from the private key by turing it into the public key
/// and dropping the private parts afterwards
impl FromKey<Ed25519PrivateKey> for Ed25519Verifier {
    type Error = InvalidSigningAlgorithmError;

    fn from_key(key: Ed25519PrivateKey, alg: JsonWebAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::EdDSA) => {
                Ok(Self(key.0.verifying_key()))
            }
            _ => Err(InvalidSigningAlgorithmError),
        }
    }
}

impl Sealed for Ed25519PrivateKey {}
impl Sealed for Ed25519PublicKey {}

impl IntoJsonWebKey for Ed25519PrivateKey {
    /// Algorithm is always [`JsonWebSigningAlgorithm::EdDSA`]
    type Algorithm = ();
    type Error = Infallible;

    fn into_jwk(self, alg: Option<impl Into<Self::Algorithm>>) -> Result<JsonWebKey, Self::Error> {
        let key = JsonWebKeyType::Asymmetric(Box::new(AsymmetricJsonWebKey::Private(
            Private::Okp(OkpPrivate::Curve25519(Curve25519Private::Ed(self))),
        )));

        let jwk = JsonWebKey::new_with_algorithm(
            key,
            alg.map(|_| JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::EdDSA)),
        );
        Ok(jwk)
    }
}

impl IntoJsonWebKey for Ed25519PublicKey {
    /// Algorithm is always [`JsonWebSigningAlgorithm::EdDSA`]
    type Algorithm = ();
    type Error = Infallible;

    fn into_jwk(self, alg: Option<impl Into<Self::Algorithm>>) -> Result<JsonWebKey, Self::Error> {
        let key = JsonWebKeyType::Asymmetric(Box::new(AsymmetricJsonWebKey::Public(Public::Okp(
            OkpPublic::Curve25519(Curve25519Public::Ed(self)),
        ))));

        let jwk = JsonWebKey::new_with_algorithm(
            key,
            alg.map(|_| JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::EdDSA)),
        );
        Ok(jwk)
    }
}

#[derive(Serialize, Deserialize)]
struct PublicRepr<'a> {
    crv: Cow<'a, str>,
    kty: Cow<'a, str>,
    x: Base64UrlBytes,
}
#[derive(Serialize, Deserialize)]
struct PrivateRepr<'a> {
    crv: Cow<'a, str>,
    kty: Cow<'a, str>,
    x: Base64UrlBytes,
    d: Base64UrlBytes,
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = PublicRepr::deserialize(deserializer)?;

        if repr.crv != CRV {
            return Err(<D::Error as Error>::custom(format!(
                "Invalid curve type `{}`. Expected `{}`",
                repr.crv, CRV
            )));
        }
        if repr.kty != KTY {
            return Err(<D::Error as Error>::custom(format!(
                "Invalid key type `{}`. Expected `{}`",
                repr.kty, KTY
            )));
        }
        let key = VerifyingKey::from_bytes((*repr.x.0).try_into().map_err(|_| {
            <D::Error as Error>::invalid_length(
                repr.x.0.len(),
                &"a base64url encoded 32 byte array",
            )
        })?)
        .map_err(<D::Error as Error>::custom)?;
        Ok(Self(key))
    }
}
impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let repr = PublicRepr {
            crv: CRV.into(),
            kty: KTY.into(),
            x: Base64UrlBytes(self.0.as_bytes().to_vec()),
        };
        repr.serialize(serializer)
    }
}

// one public key corresponds to one private/secret key
impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.verifying_key() == other.0.verifying_key()
    }
}
impl Eq for Ed25519PrivateKey {}

impl<'de> Deserialize<'de> for Ed25519PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = PrivateRepr::deserialize(deserializer)?;
        if repr.crv != CRV {
            return Err(<D::Error as Error>::custom(format!(
                "Invalid curve type `{}`. Expected `{}`",
                repr.crv, CRV
            )));
        }
        if repr.kty != KTY {
            return Err(<D::Error as Error>::custom(format!(
                "Invalid key type `{}`. Expected `{}`",
                repr.kty, KTY
            )));
        }
        let public_key = VerifyingKey::from_bytes((*repr.x.0).try_into().map_err(|_| {
            <D::Error as Error>::invalid_length(
                repr.x.0.len(),
                &"a base64url encoded 32 byte array",
            )
        })?)
        .map_err(<D::Error as Error>::custom)?;

        let signing_key = SigningKey::from_bytes((*repr.d.0).try_into().map_err(|_| {
            <D::Error as Error>::invalid_length(
                repr.d.0.len(),
                &"a base64url encoded 32 byte array",
            )
        })?);

        if public_key != signing_key.verifying_key() {
            return Err(<D::Error as Error>::custom(
                "public and private key part do not match",
            ));
        }

        Ok(Self(signing_key))
    }
}
impl Serialize for Ed25519PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let repr = PrivateRepr {
            crv: CRV.into(),
            kty: KTY.into(),
            x: Base64UrlBytes(self.0.verifying_key().to_bytes().to_vec()),
            d: Base64UrlBytes(self.0.to_bytes().to_vec()),
        };
        repr.serialize(serializer)
    }
}
