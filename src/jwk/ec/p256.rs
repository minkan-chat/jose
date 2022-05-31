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

    use super::{P256PrivateKey, P256PublicKey};

    const ENC_PUB: &str = include_str!("../../../tests/keys/p256.enc.pub.json");
    const ENC: &str = include_str!("../../../tests/keys/p256.enc.json");
    const SIG_PUB: &str = include_str!("../../../tests/keys/p256.sig.pub.json");
    const SIG: &str = include_str!("../../../tests/keys/p256.sig.json");

    #[test]
    fn deserialize_public() {
        let _: P256PublicKey = serde_json::from_str(ENC_PUB).unwrap();
        let _: P256PublicKey = serde_json::from_str(SIG_PUB).unwrap();
    }

    #[test]
    fn deserialize_private() {
        let _: P256PrivateKey = serde_json::from_str(ENC).unwrap();
        let _: P256PrivateKey = serde_json::from_str(SIG).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let private: P256PrivateKey = serde_json::from_str(SIG).unwrap();
        let message = "hello world";
        let signer: SigningKey = private.0.into();
        let signature: Signature = Signer::sign(&signer, message.as_bytes());

        let public: P256PublicKey = serde_json::from_str(SIG_PUB).unwrap();
        let verifier: VerifyingKey = public.0.into();
        Verifier::verify(&verifier, message.as_bytes(), &signature).unwrap();
    }
}
