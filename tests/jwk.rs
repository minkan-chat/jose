fn read_key_file(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/keys/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name,
    ))
    .unwrap()
}

pub mod rsa {
    use jose::jwk::rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::Value;

    use super::*;

    #[test]
    fn private_key_roundtrip() {
        let json = read_key_file("rsa");
        let json = serde_json::from_str::<Value>(&json).unwrap();

        let key: RsaPrivateKey = serde_json::from_value(json.clone()).unwrap();

        let json2 = serde_json::to_value(&key).unwrap();

        let key2: RsaPrivateKey = serde_json::from_value(json2.clone()).unwrap();
        assert_eq!(key, key2);

        assert_eq!(json["kty"], json2["kty"]);
        assert_eq!(json["n"], json2["n"]);
        assert_eq!(json["e"], json2["e"]);
        assert_eq!(json["d"], json2["d"]);
        assert_eq!(json["p"], json2["p"]);
        assert_eq!(json["q"], json2["q"]);
        assert_eq!(json["dp"], json2["dp"]);
        assert_eq!(json["dq"], json2["dq"]);
        assert_eq!(json["di"], json2["di"]);
    }

    #[test]
    fn public_key_roundtrip() {
        let json = read_key_file("rsa.pub");
        let json = serde_json::from_str::<Value>(&json).unwrap();

        let key: RsaPublicKey = serde_json::from_value(json.clone()).unwrap();

        let json2 = serde_json::to_value(&key).unwrap();

        let key2: RsaPublicKey = serde_json::from_value(json2.clone()).unwrap();
        assert_eq!(key, key2);

        assert_eq!(json["kty"], json2["kty"]);
        assert_eq!(json["n"], json2["n"]);
        assert_eq!(json["e"], json2["e"]);
    }

    // FIXME: tests for missing primes, `oth` field, etc
}

pub mod ec_p256 {
    use jose::jwk::ec::p256::{P256PrivateKey, P256PublicKey};
    // use p256::ecdsa::{
    // signature::{Signer, Verifier},
    // Signature, SigningKey, VerifyingKey,
    //};
    use serde_json::Value;

    use super::*;

    #[test]
    fn private_key_roundtrip() {
        let json = read_key_file("p256.sig");
        let json = serde_json::from_str::<Value>(&json).unwrap();

        let key: P256PrivateKey = serde_json::from_value(json.clone()).unwrap();

        let json2 = serde_json::to_value(&key).unwrap();

        let key2: P256PrivateKey = serde_json::from_value(json2.clone()).unwrap();
        assert_eq!(key, key2);

        assert_eq!(json["kty"], json2["kty"]);
        assert_eq!(json["crv"], json2["crv"]);
        assert_eq!(json["e"], json2["e"]);
        assert_eq!(json["x"], json2["x"]);
        assert_eq!(json["y"], json2["y"]);
        assert_eq!(json["d"], json2["d"]);
    }

    #[test]
    fn public_key_roundtrip() {
        let json = read_key_file("p256.sig.pub");
        let json = serde_json::from_str::<Value>(&json).unwrap();

        let key: P256PublicKey = serde_json::from_value(json.clone()).unwrap();

        let json2 = serde_json::to_value(&key).unwrap();

        let key2: P256PublicKey = serde_json::from_value(json2.clone()).unwrap();
        assert_eq!(key, key2);

        assert_eq!(json["kty"], json2["kty"]);
        assert_eq!(json["crv"], json2["crv"]);
        assert_eq!(json["x"], json2["x"]);
        assert_eq!(json["y"], json2["y"]);
    }
}
