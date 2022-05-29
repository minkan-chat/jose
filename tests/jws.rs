// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params
// - checking critical property

use std::str::FromStr;

use jose::{
    format::Compact, jwa::JsonWebSigningAlgorithm, Signable, Signer, Unverified, Verifier, JWS,
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
