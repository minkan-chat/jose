//! Key types for the P-256 curve
use elliptic_curve::{PublicKey, SecretKey};
use p256::NistP256;

/// A P-256 public key used to verify signatures and/or encrypt
#[derive(Debug)]
pub struct P256PublicKey(pub(super) PublicKey<NistP256>);
/// A P-256 private key used to create signatures and/or decrypt
#[derive(Debug)]
pub struct P256PrivateKey(pub(super) SecretKey<NistP256>);

#[cfg(test)]
mod tests {
    use p256::ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    const VALID_PRIVATE_KEY: &str = r#"
{
  "use": "enc",
  "kty": "EC",
  "kid": "UYa89vgc4u_lpcbbmDQfYJQRAUD4AED8H8FUNjk5KyQ",
  "crv": "P-256",
  "x": "hFc6OfbgRsYFOWyhGbWH0sS5DZBjJLGABJvPttVZfA4",
  "y": "tnXB8ks0-AZJKOgbMWJrE5Jm3nTFy0UiqQugmx9jku4",
  "d": "U7b2FqvDSIMFUF0FTea7Z-K8Fk0Xyb2qJlw62USEm04"
} "#;

    const VALID_PUBLIC_KEY: &str = r#"
           {
  "use": "enc",
  "kty": "EC",
  "kid": "UYa89vgc4u_lpcbbmDQfYJQRAUD4AED8H8FUNjk5KyQ",
  "crv": "P-256",
  "x": "hFc6OfbgRsYFOWyhGbWH0sS5DZBjJLGABJvPttVZfA4",
  "y": "tnXB8ks0-AZJKOgbMWJrE5Jm3nTFy0UiqQugmx9jku4"
} "#;
    use super::{P256PrivateKey, P256PublicKey};

    #[test]
    fn deserialize_public() {
        let _: P256PublicKey = serde_json::from_str(VALID_PUBLIC_KEY).unwrap();
    }

    #[test]
    fn deserialize_private() {
        let _: P256PrivateKey = serde_json::from_str(VALID_PRIVATE_KEY).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let private: P256PrivateKey = serde_json::from_str(VALID_PRIVATE_KEY).unwrap();
        let message = "hello world";
        let signer: SigningKey = private.0.into();
        let signature: Signature = Signer::sign(&signer, message.as_bytes());

        let public: P256PublicKey = serde_json::from_str(VALID_PUBLIC_KEY).unwrap();
        let verifier: VerifyingKey = public.0.into();
        Verifier::verify(&verifier, message.as_bytes(), &signature).unwrap();
    }
}
