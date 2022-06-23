// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params
// - checking critical property

use std::str::FromStr;

use jose::{
    format::Compact,
    jwa::{EcDSA, JsonWebSigningAlgorithm},
    jwk::ec::{p256::P256PrivateKey, P256Signer},
    IntoSigner, Signable, Signer, Unverified, Verifier, JWS,
};

#[test]
fn smoke() {
    let jws = JWS::builder().build(String::from("abc"));

    struct NoneKey;

    impl Signer<&'static [u8]> for NoneKey {
        fn sign(&self, _: &[u8]) -> Result<&'static [u8], signature::Error> {
            Ok(&[])
        }

        fn algorithm(&self) -> JsonWebSigningAlgorithm {
            JsonWebSigningAlgorithm::None
        }
    }

    let c = jws.sign(&NoneKey).unwrap().encode::<Compact>();

    std::println!("{}", c);
}

#[test]
fn verify() {
    let raw = "eyJhbGciOiJub25lIn0.YWJj.";
    let input = Compact::from_str(raw).unwrap();

    struct NoneVerifier;
    impl Verifier for NoneVerifier {
        fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), jose::VerifyError> {
            Ok(())
        }
    }

    let jws = Unverified::<JWS<String>>::decode(input)
        .unwrap()
        .verify(&NoneVerifier)
        .unwrap();
    dbg!(jws);
}

#[test]
fn sign_jws_using_p256() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/p256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: P256PrivateKey = serde_json::from_str(&key).unwrap();
    let signer: P256Signer = key
        .into_signer(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256))
        .unwrap();

    let jws = JWS::builder()
        .critical(vec![String::from("foo")])
        .build(String::from("abc"))
        .sign(&signer)
        .unwrap();

    println!("{}", jws.encode::<Compact>());
}
