// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params

use std::{convert::Infallible, str::FromStr, string::FromUtf8Error};

use jose::{
    format::{Compact, JsonFlattened, JsonGeneral},
    header::HeaderValue,
    jwa::{EcDSA, JsonWebSigningAlgorithm},
    jwk::{
        ec::p256::{P256PrivateKey, P256Signer},
        okp::curve25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signer, Ed25519Verifier},
        JwkSigner, JwkVerifier,
    },
    jws::{
        FromRawPayload, IntoPayload, IntoSigner, IntoVerifier, ManyUnverified, PayloadKind, Signer,
        Unverified, Verifier,
    },
    policy::{Checkable, StandardPolicy},
    Base64UrlString, JsonWebKey, Jws,
};

fn read_key_file(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/keys/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name,
    ))
    .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct StringPayload(String);

impl From<&str> for StringPayload {
    fn from(value: &str) -> Self {
        StringPayload(value.to_string())
    }
}

impl FromRawPayload for StringPayload {
    type Error = FromUtf8Error;

    fn from_raw_payload(payload: PayloadKind) -> Result<Self, Self::Error> {
        match payload {
            PayloadKind::Standard(s) => String::from_utf8(s.decode()).map(StringPayload),
        }
    }
}

impl IntoPayload for StringPayload {
    type Error = Infallible;

    fn into_payload(self) -> Result<PayloadKind, Self::Error> {
        let s = Base64UrlString::encode(self.0);
        Ok(PayloadKind::Standard(s))
    }
}

struct NoneKey;
impl Signer<[u8; 0]> for NoneKey {
    fn sign(&mut self, _msg: &[u8]) -> Result<[u8; 0], signature::Error> {
        Ok([])
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        JsonWebSigningAlgorithm::None
    }

    fn key_id(&self) -> Option<&str> {
        Some("none")
    }
}

struct NoneVerifier;
impl Verifier for NoneVerifier {
    fn verify(&mut self, _: &[u8], _: &[u8]) -> Result<(), signature::Error> {
        Ok(())
    }
}

#[test]
fn signer_without_key_id() {
    let signer = NoneKey;

    assert_eq!(signer.key_id(), Some("none"));

    let without_key_id = signer.without_key_id();

    assert_eq!(without_key_id.key_id(), None);
}

#[test]
fn none_verifier_roundtrip() {
    let jws = Jws::<Compact, _>::builder()
        .build(StringPayload::from("abc"))
        .unwrap();
    let jws_compact = jws.sign(&mut NoneKey.without_key_id()).unwrap().encode();

    assert_eq!(
        jws_compact.to_string(),
        String::from("eyJhbGciOiJub25lIn0.YWJj.")
    );

    let parsed_jws = Unverified::<Jws<Compact, StringPayload>>::decode(jws_compact)
        .unwrap()
        .verify(&mut NoneVerifier)
        .unwrap();

    assert_eq!(parsed_jws.payload(), &StringPayload::from("abc"));
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

    let jws = Jws::<Compact, _>::builder()
        .build(StringPayload::from("hello world!"))
        .unwrap()
        .sign(&mut signer)
        .unwrap()
        .encode();

    assert_eq!(
        jws.to_string().as_str(),
        "eyJhbGciOiJFUzI1NiJ9.aGVsbG8gd29ybGQh.\
         lVKmpTNK_Im3-JEpF1JzuXM-vP9tNSkR8785hqnYzOHd1__VVOeMzGW7nywUe7Xkp6Wlu3KgWXlvsxhQdU1PlQ"
    );
}

#[test]
fn deny_compact_jws_with_empty_protected_header() {
    let jws: Jws<Compact, StringPayload> = Jws::builder()
        .header(|b| b.algorithm(HeaderValue::Unprotected(JsonWebSigningAlgorithm::None)))
        .build(StringPayload::from("abc"))
        .unwrap();

    jws.sign(&mut NoneKey).unwrap_err();
}

#[test]
fn json_flattened_jws_with_no_protected_header() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/cookbook_hs256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: JsonWebKey = serde_json::from_str(&key).unwrap();
    let key = key.check(StandardPolicy::new()).unwrap();

    let mut signer = JwkSigner::try_from(key).unwrap();

    let payload = "It's a dangerous business, Frodo, going out your door. You step onto the road, \
                   and if you don't keep your feet, there's no knowing where you";

    let jws: Jws<JsonFlattened, StringPayload> = Jws::builder()
        .header(|b| b.algorithm(HeaderValue::Unprotected(JsonWebSigningAlgorithm::None)))
        .build(StringPayload::from(payload))
        .unwrap();

    let jws = jws.sign(&mut signer).unwrap();

    println!("{:#}", jws);
}

#[test]
fn smoke() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/p256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key2 = std::fs::read_to_string(format!(
        "{}/tests/keys/hs256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: JsonWebKey = serde_json::from_str(&key).unwrap();
    let key = key.check(StandardPolicy::new()).unwrap();

    let key2: JsonWebKey = serde_json::from_str(&key2).unwrap();
    let key2 = key2.check(StandardPolicy::new()).unwrap();

    let mut signer = JwkSigner::try_from(key.clone()).unwrap();
    let mut signer2 = JwkSigner::try_from(key2.clone()).unwrap();

    let mut verifier = JwkVerifier::try_from(key).unwrap();
    let mut verifier2 = JwkVerifier::try_from(key2).unwrap();

    let payload = r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#;
    let payload = StringPayload::from(payload);

    let signers: [&mut dyn Signer<Vec<u8>>; 2] = [&mut signer, &mut signer2];

    let jws = Jws::<JsonGeneral, _>::builder()
        .header(|b| b)
        .header(|b| b)
        .build(payload)
        .unwrap()
        .sign_many(signers)
        .unwrap()
        .encode();
    println!("{}", jws);

    let verifiers: [&mut dyn Verifier; 2] = [&mut verifier, &mut verifier2];
    let parsed_jws = ManyUnverified::<Jws<JsonGeneral, StringPayload>>::decode(jws)
        .unwrap()
        .verify_many(verifiers)
        .unwrap();

    println!("{:#?}", parsed_jws);
}

#[test]
fn additional_jwk_parameters_in_header() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/p256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Additional {
        #[serde(rename = "example.com/custom-key")]
        foo: usize,
    }

    let additional = Additional { foo: 1337 };

    let key: JsonWebKey = serde_json::from_str(&key).unwrap();
    let key = key.check(StandardPolicy::new()).unwrap();
    let mut signer = JwkSigner::try_from(key.clone()).unwrap();
    let mut verifier = JwkVerifier::try_from(key.clone()).unwrap();

    let key = key
        .into_inner()
        .0
        .into_builder()
        .additional(additional)
        .build()
        .unwrap();
    let key = key.into_untyped_additional().unwrap();

    let jws: Jws<Compact, StringPayload> = Jws::builder()
        .header(|b| b.json_web_key(Some(HeaderValue::Protected(key))))
        .build(StringPayload::from("abc"))
        .unwrap();

    let jws = jws.sign(&mut signer).unwrap().encode();

    let parsed_jws = Unverified::<Jws<Compact, StringPayload>>::decode(jws)
        .unwrap()
        .verify(&mut verifier)
        .unwrap();

    let jwk = parsed_jws
        .header()
        .json_web_key()
        .unwrap()
        .into_inner()
        .clone();
    let jwk: JsonWebKey<Additional> = jwk.deserialize_additional().unwrap();

    assert_eq!(jwk.additional().foo, 1337);
}

#[test]
fn ed25519() {
    let private: Ed25519PrivateKey =
        serde_json::from_str(&read_key_file("ed25519")).expect("valid ed25519 private key");
    let _wrong_private = serde_json::from_str::<Ed25519PrivateKey>(&read_key_file("ed25519.pub"))
        .expect_err("is a public key");

    let public: Ed25519PublicKey =
        serde_json::from_str(&read_key_file("ed25519.pub")).expect("is a valid public key");
    let _wrong_public = serde_json::from_str::<Ed25519PublicKey>(&read_key_file("ed25519"))
        .expect("public key can be parsed from private key");

    let msg = "I was cured all right.";

    let mut signer: Ed25519Signer = private
        .into_signer(jose::jwa::JsonWebSigningAlgorithm::EdDSA)
        .unwrap();

    let jws = Jws::<Compact, _>::builder()
        .build(StringPayload(msg.to_string()))
        .unwrap();

    let jws = jws.sign(&mut signer).unwrap();

    println!("{:#?}", jws);

    let mut verifier: Ed25519Verifier = public
        .into_verifier(JsonWebSigningAlgorithm::EdDSA)
        .unwrap();

    let encoded = jws.encode().to_string();
    assert_eq!(
        encoded,
        "eyJhbGciOiJFZERTQSJ9.SSB3YXMgY3VyZWQgYWxsIHJpZ2h0Lg.\
         JtDl6Eq4ORiI_fYmeik8QLMUPur0s37AgaK-o8W2ywEXnomeSPpf3Je0EvCI8K55k0uu0zkdHmGs2vu-DiuLDw"
    );

    let unverified_jws =
        Unverified::<Jws<Compact, StringPayload>>::decode(Compact::from_str(&encoded).unwrap())
            .unwrap();
    unverified_jws
        .verify(&mut verifier)
        .expect("valid signature");

    let signature_by_different_key =
        "eyJhbGciOiJFZERTQSJ9.SSB3YXMgY3VyZWQgYWxsIHJpZ2h0Lg.\
         xuBNTX8MSX1Du5sAdSGBUKijn8yqHG8v-3CYrZpoHizzwU9T6aT-XqbS5FBuMR9_pGagmpO6EiPHqZiTUpxXDQ";

    let wrong_jws: Unverified<Jws<Compact, StringPayload>> =
        Unverified::decode(Compact::from_str(signature_by_different_key).unwrap()).unwrap();

    wrong_jws
        .verify(&mut verifier)
        .expect_err("signature made by different private key");
}
