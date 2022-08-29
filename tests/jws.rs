// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params

use std::{convert::Infallible, str::FromStr, string::FromUtf8Error};

use jose::{
    format::Compact,
    jwa::{EcDSA, Hmac, JsonWebSigningAlgorithm},
    jwk::{
        ec::p256::{P256PrivateKey, P256Signer},
        symmetric::hmac::{HmacKey, Hs256},
        JwkSigner, SymmetricJsonWebKey,
    },
    jws::{
        FromRawPayload, IntoSigner, ParseCompactError, PayloadKind, ProvidePayload, Signer,
        Unverified, Verifier,
    },
    policy::{Checkable, StandardPolicy},
    Base64UrlString, JsonWebKey, JWS,
};

#[derive(Debug)]
struct StringPayload(String);

impl FromRawPayload for StringPayload {
    type Error = FromUtf8Error;

    fn from_raw_payload(payload: PayloadKind) -> Result<Self, Self::Error> {
        match payload {
            PayloadKind::Standard(s) => String::from_utf8(s.decode()).map(StringPayload),
        }
    }
}

impl ProvidePayload for StringPayload {
    type Error = Infallible;

    fn provide_payload<D: digest::Update>(
        self,
        digest: &mut D,
    ) -> Result<PayloadKind, Self::Error> {
        let s = Base64UrlString::encode(self.0);
        digest.update(s.as_bytes());
        Ok(PayloadKind::Standard(s))
    }
}

struct DummyDigest;
impl digest::Update for DummyDigest {
    fn update(&mut self, _data: &[u8]) {}
}

struct NoneKey;
impl Signer<[u8; 0]> for NoneKey {
    type Digest = DummyDigest;

    fn new_digest(&self) -> Self::Digest {
        DummyDigest
    }

    fn sign_digest(&mut self, _digest: Self::Digest) -> Result<[u8; 0], signature::Error> {
        Ok([])
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
        .build(StringPayload(String::from("")))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    let err = Unverified::<JWS<StringPayload>>::decode(jws).unwrap_err();
    assert_eq!(
        err,
        ParseCompactError::<FromUtf8Error>::UnsupportedCriticalHeader
    );
}

#[test]
fn allow_jws_with_empty_crit_header() {
    let jws = JWS::builder()
        .critical(vec![])
        .build(StringPayload(String::from("")))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    Unverified::<JWS<StringPayload>>::decode(jws).unwrap();
}

#[test]
fn smoke() {
    let jws = JWS::builder().build(StringPayload(String::from("abc")));

    let c = jws.sign(&mut NoneKey).unwrap().encode::<Compact>();

    std::println!("{}", c);
}

#[test]
fn verify() {
    let raw = "eyJhbGciOiJub25lIn0.YWJj.";
    let input = Compact::from_str(raw).unwrap();

    let jws = Unverified::<JWS<StringPayload>>::decode(input)
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
        .build(StringPayload(String::from("abc")))
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
                .build(StringPayload("Here be dragons".to_string()))
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
        .build(StringPayload("Here be dragons".to_string()))
        .sign(&mut signer)
        .unwrap();

    println!("{}", jws.encode::<Compact>());
}
