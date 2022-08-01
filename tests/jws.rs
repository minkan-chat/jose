// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params

use std::{str::FromStr, string::FromUtf8Error};

use jose::{
    format::Compact,
    jwa::{EcDSA, Hmac, JsonWebSigningAlgorithm},
    jwk::{
        ec::p256::{P256PrivateKey, P256Signer},
        symmetric::hmac::{HmacKey, Hs256},
        JwkSigner, SymmetricJsonWebKey,
    },
    jws::{IntoSigner, ParseCompactError, Signer, Unverified, Verifier},
    policy::{Checkable, StandardPolicy},
    JsonWebKey, JWS,
};

struct NoneKey;
impl Signer<&'static [u8]> for NoneKey {
    type Digest = sha2::Sha256;

    fn new_digest(&self) -> Self::Digest {
        todo!()
    }

    fn finalize(&mut self, _digest: Self::Digest) -> Result<&'static [u8], signature::Error> {
        todo!()
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        JsonWebSigningAlgorithm::None
    }
}

struct NoneVerifier;
impl Verifier for NoneVerifier {
    fn verify(&mut self, _: &[u8], _: &[u8]) -> Result<(), signature::Error> {
        Ok(())
    }
}

#[test]
fn deny_jws_with_unsupported_crit_header() {
    let jws = JWS::builder()
        .critical(vec!["foo".into()])
        .build(String::from(""))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    let err = Unverified::<JWS<String>>::decode(jws).unwrap_err();
    assert_eq!(
        err,
        ParseCompactError::<FromUtf8Error>::UnsupportedCriticalHeader
    );
}

#[test]
fn allow_jws_with_empty_crit_header() {
    let jws = JWS::builder()
        .critical(vec![])
        .build(String::from(""))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    Unverified::<JWS<String>>::decode(jws).unwrap();
}

#[test]
fn smoke() {
    let jws = JWS::builder().build(String::from("abc"));

    let c = jws.sign(&mut NoneKey).unwrap().encode::<Compact>();

    std::println!("{}", c);
}

#[test]
fn verify() {
    let raw = "eyJhbGciOiJub25lIn0.YWJj.";
    let input = Compact::from_str(raw).unwrap();

    let jws = Unverified::<JWS<String>>::decode(input)
        .unwrap()
        .verify(&mut NoneVerifier)
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
    let mut signer: P256Signer = key
        .into_signer(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256))
        .unwrap();

    let jws = JWS::builder()
        .build(String::from("abc"))
        .sign(&mut signer)
        .unwrap();

    println!("{}", jws.encode::<Compact>());
}

#[test]
fn sign_jws_using_hs256() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/hs256.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();

    let key: SymmetricJsonWebKey = serde_json::from_str(&key).unwrap();

    match key {
        SymmetricJsonWebKey::OctetSequence(ref key) => {
            let mut signer: HmacKey<Hs256> = key
                .into_signer(JsonWebSigningAlgorithm::Hmac(Hmac::Hs256))
                .unwrap();
            let jws = JWS::builder()
                .build("Here be dragons".to_string())
                .sign(&mut signer)
                .unwrap();

            println!("{}", jws.encode::<Compact>());
        }
        _ => panic!("unexpected key type"),
    }
}

#[test]
fn sign_jws_using_rsa() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/rsa.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();

    let key = serde_json::from_str::<JsonWebKey>(&key)
        .unwrap()
        .check(StandardPolicy::default())
        .unwrap();

    let mut signer: JwkSigner = key.try_into().unwrap();

    let jws = JWS::builder()
        .build("Here be dragons".to_string())
        .sign(&mut signer)
        .unwrap();

    println!("{}", jws.encode::<Compact>());
}
