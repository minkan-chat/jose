fn read_key_file(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/keys/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name,
    ))
    .unwrap()
}

macro_rules! key_roundtrip_test {
    ($priv:ty, $pub:ty, $file:literal, [$($priv_field:literal),*$(,)?], [$($pub_field:literal),*$(,)?]$(,)?) => {
        #[test]
        fn private_key_serialisation_roundtrip() {
            let json = crate::read_key_file($file);
            let json = serde_json::from_str::<serde_json::Value>(&json).unwrap();

            let key: $priv = serde_json::from_value(json.clone()).unwrap();

            let json2 = serde_json::to_value(&key).unwrap();

            let key2: $priv = serde_json::from_value(json2.clone()).unwrap();
            assert_eq!(key, key2);

            assert_eq!(json["kty"], json2["kty"]);

            $(assert_eq!(json[$priv_field], json2[$priv_field]);)*
        }

        #[test]
        fn public_key_serialisation_roundtrip() {
            let json = crate::read_key_file(&format!("{}.pub", $file));
            let json = serde_json::from_str::<serde_json::Value>(&json).unwrap();

            let key: $pub = serde_json::from_value(json.clone()).unwrap();

            let json2 = serde_json::to_value(&key).unwrap();

            let key2: $pub = serde_json::from_value(json2.clone()).unwrap();
            assert_eq!(key, key2);

            assert_eq!(json["kty"], json2["kty"]);
            $(assert_eq!(json[$pub_field], json2[$pub_field]);)*
        }
    };
}

pub mod rsa {
    key_roundtrip_test! {
        jose::jwk::rsa::RsaPrivateKey,
        jose::jwk::rsa::RsaPublicKey,
        "rsa",
        ["n", "e", "d", "p", "q", "dp", "dq", "di"],
        ["n", "e"],
    }

    // FIXME: tests for missing primes, `oth` field, etc
}

pub mod ec_p256 {
    key_roundtrip_test! {
        jose::jwk::ec::p256::P256PrivateKey,
        jose::jwk::ec::p256::P256PublicKey,
        "p256",
        ["crv", "e", "x", "y", "d"],
        ["crv", "x", "y"],
    }
}

pub mod ec_p384 {
    key_roundtrip_test! {
        jose::jwk::ec::p384::P384PrivateKey,
        jose::jwk::ec::p384::P384PublicKey,
        "p384",
        ["crv", "e", "x", "y", "d"],
        ["crv", "x", "y"],
    }
}

pub mod ec {
    use jose::jwk::ec::{EcPrivate, EcPublic};

    use super::*;

    #[test]
    fn parse_generic_public_key() {
        let json = read_key_file("p256.pub");
        let key: EcPublic = serde_json::from_str(&json).unwrap();
        assert!(matches!(key, EcPublic::P256(..)));
    }

    #[test]
    fn parse_generic_private_key() {
        let json = read_key_file("p256");
        let key: EcPrivate = serde_json::from_str(&json).unwrap();
        assert!(matches!(key, EcPrivate::P256(..)));
    }
}
