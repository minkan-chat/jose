// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params
// - checking critical property

use jose::{
    format::{Compact, Json},
    jwa::JsonWebSigningAlgorithm,
    jws::JsonWebSignature,
    Signable, Signer,
};

#[test]
fn smoke() {
    let jws = JsonWebSignature::builder().build(String::from("abc"));

    struct NoneKey;

    impl Signer<&'static [u8]> for NoneKey {
        fn sign(&self, _: &[u8]) -> Result<&'static [u8], signature::Error> {
            Ok(&[])
        }

        fn algorithm(&self) -> JsonWebSigningAlgorithm {
            JsonWebSigningAlgorithm::None
        }
    }

    let c = jws.sign(&NoneKey).unwrap().encode::<Json>();

    std::println!("{}", c);
}
