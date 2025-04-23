use jose::{
    crypto::hmac,
    jwa::{EcDSA, Hmac, JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jwk::{
        symmetric::{FromOctetSequenceError, OctetSequence},
        AsymmetricJsonWebKey, EcPrivate, EcPublic, FromKey as _, JsonWebKey, JsonWebKeyType,
        JwkSigner, OkpPrivate, Private, Public, Thumbprint,
    },
    jws::Signer,
    policy::{Checkable, Checked, StandardPolicy},
    Base64UrlString,
};
use serde_json::json;

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
            let json_str = crate::read_key_file($file);
            let json = serde_json::from_str::<serde_json::Value>(&json_str).unwrap();

            let key: $priv = serde_json::from_str(&json_str).unwrap();

            let json2 = serde_json::to_value(&key).unwrap();

            let key2: $priv = serde_json::from_value(json2.clone()).unwrap();
            assert_eq!(key, key2);

            assert_eq!(json["kty"], json2["kty"]);

            $(assert_eq!(json[$priv_field], json2[$priv_field]);)*
        }

        #[test]
        fn public_key_serialisation_roundtrip() {
            let json_str = crate::read_key_file(&format!("{}.pub", $file));
            let json = serde_json::from_str::<serde_json::Value>(&json_str).unwrap();

            let key: $pub = serde_json::from_str(&json_str).unwrap();

            let json2 = serde_json::to_value(&key).unwrap();

            let key2: $pub = serde_json::from_value(json2.clone()).unwrap();
            assert_eq!(key, key2);

            assert_eq!(json["kty"], json2["kty"]);
            $(assert_eq!(json[$pub_field], json2[$pub_field]);)*
        }
    };
}

pub mod rsa {
    use jose::crypto::rsa;

    key_roundtrip_test! {
        rsa::PrivateKey,
        rsa::PublicKey,
        "rsa",
        ["n", "e", "d", "p", "q", "dp", "dq", "di"],
        ["n", "e"],
    }

    #[test]
    fn deny_key_with_other_primes() {
        let json = r#"{
            "use":"sig",
            "kty":"RSA",
            "kid":"nYPs6qc5zj3VOVKr4yY-EzirO-AcdUl0JC5bcXKGE6Y",
            "alg":"RS256",
            "n":"vxmzEVX_Fus8i8BWT_sC_m389t615iPxKSMavPFv0xEhES42RWkO6yNpb_cwWhlJtoy_UdiRW8-0DHYJIbpiwkw4oRRnfMYX4FU77yjovSQLEhKPfIuYDBuP-9LQgF8_NgB9z1WokSUcH-tAf_35MpiXptGxoFuIe1EE7u1TWpTnMwGBnqO1EvJltyWej9R6rt47oqizn1VN8P2No3tys181B_TE9c6N2tXzWpnm5QY7UZO2zPLtYFGbj7hJCNhc5SL3vt-81KkaNjPcW1rgCIoRKvHVI79n_H81LQdiJDJyIobtvPH3XFQa_tM4CP2ul121E_Zi0tcjuD1zyLCq7Q",
            "e":"AQAB",
            "d":"n0FzkYbxRtBTbMOlKpItNIvEvJdtT5W0bGvs5HjwkB0-SWsRn1amMB8ax0xg5zUb0R4KctLgkHrPuXLEuW7yzqlmqBaxB7KuQy3E_NJC4x0efLkrCsfqtmxh2aMeT10Q-JgAQMFJ8WvTvGX5IrEs85VnDIbEWLbvTpV-Xv8478qjjt4v91wyhlzZW8A5-fsluy9faZDgKm3a3RaAKzP15ouffYf3ui5CTckXB-50fcrDasNEYlXzUzS1rHgQjF16ApjN7WupFP-FnlDkxudt6VfWmErakQV3iQVinpbqXU4IhtxgthgUOPQPP7cMvV1IVTWT8pHEdv7XZySFUHOwoQ",
            "p":"wI-kPWTpm34wn0O1KzvCweAUBGJm-6s4R_sdkhE62Aht9NuGE86Z6zFfb6HI-dI6bvwPBNEROKNumrlsABgR13m9AVGFwq4OP-ipI4BVXpxMWi6tnKYFPegP21lDHk9p1cu_LIBWSq-GmqUtZo5Qz3suKeKOKmUNeo3VvM963Vc",
            "q":"_g7dBzo7f002nuzQO0Ie_2Mb1lBXkmcEXLeouSdwLyYUSH4kuJFVuaq404NknFHotB8wjajP8V3w8s6oscO_2qcLcIeOJOVHvpoVJp0XodFPJteC8ROR2epzkjSxNh_j_plHcCd0ly8IVcWmgoZdf6pjeSfbFPO3OB48wimAy1s",
            "dp":"e3jfoHpfjNP6i3UX6zPzqutrCnCqhj-A5C7yBCJGMBYfo31L2NGGQpgzENqVixMxYs7_NmB0gXPSTSYOSXUlo5wtBHZopa-D9ZjTM69rjjH8h2sc6bBO9iYiXM08y2eyfmOaHwffzR4F2o2FshgZWyEqNbNO44JOhUIDRoFn0Bs",
            "dq":"Hd9tid4FBPD1TTaXPYCG2Iy0xzxnL6XBU42c3ziN7l1R4TxD4RfltpEmbmhyuha_f_5y3RVObhkXrdUy7MQRmQovRCoMQrZa-0Ru3D14e-R6pByPHv2oFrGEqVpcw_p3-oXXao6ZHPXAyyUUcSCPeeV1ENfo4MvPbV_Q0RvEMyU",
            "qi":"srk3oe6CxebsQo1QTTygg-dWBlXongHf2m4Asj7GBeswoa49NcqzUvv5wlWuTgKJeihjjp-L5lkC5JWiFfUpRkBqr7tUE9faUmDa6fPLlvqWcB9A04rrZ3aJYqHgJJZ9e6OrEKwhgliIYSsTxlD-bLGZVLj-dp0R7xSVOFqiRX0",
            "oth": []
        }"#;

        let err = serde_json::from_str::<rsa::PrivateKey>(json).unwrap_err();
        assert_eq!(
            err.to_string(),
            "RSA private keys with `oth` field set are not supported"
        );
    }

    #[test]
    fn deny_key_with_missing_prime() {
        let json = r#"{
            "use":"sig",
            "kty":"RSA",
            "kid":"nYPs6qc5zj3VOVKr4yY-EzirO-AcdUl0JC5bcXKGE6Y",
            "alg":"RS256",
            "n":"vxmzEVX_Fus8i8BWT_sC_m389t615iPxKSMavPFv0xEhES42RWkO6yNpb_cwWhlJtoy_UdiRW8-0DHYJIbpiwkw4oRRnfMYX4FU77yjovSQLEhKPfIuYDBuP-9LQgF8_NgB9z1WokSUcH-tAf_35MpiXptGxoFuIe1EE7u1TWpTnMwGBnqO1EvJltyWej9R6rt47oqizn1VN8P2No3tys181B_TE9c6N2tXzWpnm5QY7UZO2zPLtYFGbj7hJCNhc5SL3vt-81KkaNjPcW1rgCIoRKvHVI79n_H81LQdiJDJyIobtvPH3XFQa_tM4CP2ul121E_Zi0tcjuD1zyLCq7Q",
            "e":"AQAB",
            "d":"n0FzkYbxRtBTbMOlKpItNIvEvJdtT5W0bGvs5HjwkB0-SWsRn1amMB8ax0xg5zUb0R4KctLgkHrPuXLEuW7yzqlmqBaxB7KuQy3E_NJC4x0efLkrCsfqtmxh2aMeT10Q-JgAQMFJ8WvTvGX5IrEs85VnDIbEWLbvTpV-Xv8478qjjt4v91wyhlzZW8A5-fsluy9faZDgKm3a3RaAKzP15ouffYf3ui5CTckXB-50fcrDasNEYlXzUzS1rHgQjF16ApjN7WupFP-FnlDkxudt6VfWmErakQV3iQVinpbqXU4IhtxgthgUOPQPP7cMvV1IVTWT8pHEdv7XZySFUHOwoQ",
            "p":"wI-kPWTpm34wn0O1KzvCweAUBGJm-6s4R_sdkhE62Aht9NuGE86Z6zFfb6HI-dI6bvwPBNEROKNumrlsABgR13m9AVGFwq4OP-ipI4BVXpxMWi6tnKYFPegP21lDHk9p1cu_LIBWSq-GmqUtZo5Qz3suKeKOKmUNeo3VvM963Vc",
            "q":"_g7dBzo7f002nuzQO0Ie_2Mb1lBXkmcEXLeouSdwLyYUSH4kuJFVuaq404NknFHotB8wjajP8V3w8s6oscO_2qcLcIeOJOVHvpoVJp0XodFPJteC8ROR2epzkjSxNh_j_plHcCd0ly8IVcWmgoZdf6pjeSfbFPO3OB48wimAy1s",
            "dq":"Hd9tid4FBPD1TTaXPYCG2Iy0xzxnL6XBU42c3ziN7l1R4TxD4RfltpEmbmhyuha_f_5y3RVObhkXrdUy7MQRmQovRCoMQrZa-0Ru3D14e-R6pByPHv2oFrGEqVpcw_p3-oXXao6ZHPXAyyUUcSCPeeV1ENfo4MvPbV_Q0RvEMyU",
            "qi":"srk3oe6CxebsQo1QTTygg-dWBlXongHf2m4Asj7GBeswoa49NcqzUvv5wlWuTgKJeihjjp-L5lkC5JWiFfUpRkBqr7tUE9faUmDa6fPLlvqWcB9A04rrZ3aJYqHgJJZ9e6OrEKwhgliIYSsTxlD-bLGZVLj-dp0R7xSVOFqiRX0"
        }"#;

        let err = serde_json::from_str::<rsa::PrivateKey>(json).unwrap_err();
        assert_eq!(
            err.to_string(),
            "expected `dp` to be present because all prime fields must be set if one of them is \
             set"
        );
    }
}

pub mod ec_p256 {
    key_roundtrip_test! {
        jose::crypto::ec::P256PrivateKey,
        jose::crypto::ec::P256PublicKey,
        "p256",
        ["crv", "e", "x", "y", "d"],
        ["crv", "x", "y"],
    }
}

pub mod ec_p384 {
    key_roundtrip_test! {
        jose::crypto::ec::P384PrivateKey,
        jose::crypto::ec::P384PublicKey,
        "p384",
        ["crv", "e", "x", "y", "d"],
        ["crv", "x", "y"],
    }
}

pub mod ec {
    use jose::jwk;

    use super::*;

    #[test]
    fn parse_generic_public_key() {
        let json = read_key_file("p256.pub");
        let key: jwk::EcPublic = serde_json::from_str(&json).unwrap();
        assert!(matches!(key, jwk::EcPublic::P256(..)));
    }

    #[test]
    fn parse_generic_private_key() {
        let json = read_key_file("p256");
        let key: jwk::EcPrivate = serde_json::from_str(&json).unwrap();
        assert!(matches!(key, jwk::EcPrivate::P256(..)));
    }
}

pub mod okp_ed25519 {
    key_roundtrip_test! {
        jose::jwk::OkpPrivate,
        jose::jwk::OkpPublic,
        "ed25519",
        ["crv", "x", "d"],
        ["crv", "x"],
    }
}
#[test]
fn generic_public_key_roundtrip() {
    let json = read_key_file("p256.pub");

    let key: JsonWebKeyType = serde_json::from_str(&json).unwrap();

    let inner = match key {
        JsonWebKeyType::Asymmetric(ref inner) => &**inner,
        _ => unreachable!(),
    };

    assert!(matches!(
        inner,
        AsymmetricJsonWebKey::Public(Public::Ec(EcPublic::P256(..)))
    ));

    let json2 = serde_json::to_string(&key).unwrap();
    let key2: JsonWebKeyType = serde_json::from_str(&json2).unwrap();

    assert_eq!(key, key2);
}

#[test]
fn generic_private_key_roundtrip() {
    let json = read_key_file("p256");

    let key: JsonWebKeyType = serde_json::from_str(&json).unwrap();

    let inner = match key {
        JsonWebKeyType::Asymmetric(ref inner) => &**inner,
        _ => unreachable!(),
    };

    assert!(matches!(
        inner,
        AsymmetricJsonWebKey::Private(Private::Ec(EcPrivate::P256(..)))
    ));

    let json2 = serde_json::to_string(&key).unwrap();
    let key2: JsonWebKeyType = serde_json::from_str(&json2).unwrap();

    assert_eq!(key, key2);
}

#[test]
fn serde_jwk() {
    let enc_json = read_key_file("jwk_optional_parameters_rsa_enc.pub");
    let enc: JsonWebKey = serde_json::from_str(&enc_json).unwrap();
    match enc.algorithm().unwrap() {
        JsonWebAlgorithm::Encryption(_) => (),
        _ => panic!(),
    }

    let sig_json = read_key_file("jwk_optional_parameters_rsa_sig.pub");
    let sig: JsonWebKey = serde_json::from_str(&sig_json).unwrap();
    match sig.algorithm().unwrap() {
        JsonWebAlgorithm::Signing(_) => (),
        _ => panic!(),
    }

    // It is not required for json keys to maintain order. Therefore, the input
    // and output json string might differ in the sense that keys appear in a
    // different order but by the definition of the json spec, they are the same
    // assert_eq!(sig_json, serde_json::to_string(&sig).unwrap());
}

#[test]
fn deny_duplicates_key_operations() {
    let _ok: JsonWebKey = serde_json::from_str(&read_key_file("key_ops_rsa_enc.pub")).unwrap();
    let _err = serde_json::from_str::<JsonWebKey>(&read_key_file("key_ops_duplicates_rsa_enc.pub"))
        .unwrap_err();
}

#[test]
fn jwk_signer() {
    let hs256: Checked<JsonWebKey, _> = serde_json::from_str::<JsonWebKey>(&read_key_file("hs256"))
        .unwrap()
        .check(StandardPolicy::default())
        .unwrap();
    let hs256_signer: JwkSigner = hs256.try_into().unwrap();
    assert_eq!(
        hs256_signer.algorithm(),
        JsonWebSigningAlgorithm::Hmac(Hmac::Hs256)
    );

    let p256: Checked<_, _> = serde_json::from_str::<JsonWebKey>(&read_key_file("p256"))
        .unwrap()
        .check(StandardPolicy::default())
        .unwrap();
    let p256_signer: JwkSigner = p256.try_into().unwrap();

    assert_eq!(
        p256_signer.algorithm(),
        JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256)
    );
}

#[test]
fn deny_hmac_key_with_short_key() {
    let raw_key = r#"{"kty": "oct", "k": "QUFBQQ"}"#;
    let key = serde_json::from_str::<OctetSequence>(raw_key).unwrap();

    let hmac = hmac::Key::<hmac::Hs256>::from_key(
        &key,
        JsonWebAlgorithm::Signing(JsonWebSigningAlgorithm::Hmac(Hmac::Hs256)),
    );

    assert!(matches!(
        hmac.unwrap_err(),
        FromOctetSequenceError::InvalidLength
    ));
}

#[test]
fn ed25519_json_web_key() {
    let jwk: JsonWebKey = serde_json::from_str(&read_key_file("ed25519")).unwrap();
    match jwk.key_type() {
        JsonWebKeyType::Asymmetric(key) => match **key {
            AsymmetricJsonWebKey::Private(Private::Okp(OkpPrivate::Ed25519(..))) => (),
            _ => panic!(),
        },
        _ => panic!(),
    }
}

#[test]
fn convert_to_public_key() {
    let private_json = read_key_file("p256");
    let public_json = read_key_file("p256.pub");

    let private: JsonWebKey = serde_json::from_str(&private_json).unwrap();
    let public: JsonWebKey = serde_json::from_str(&public_json).unwrap();

    let public_converted = private.clone().into_verifying_key();
    assert_eq!(public.key_type(), public_converted.key_type());

    let public_converted = private.strip_secret_material().unwrap();
    assert_eq!(public.key_type(), public_converted.key_type());
}

#[test]
fn symmetric_key_can_not_strip_secret() {
    let key = read_key_file("hs256");
    let key: JsonWebKey = serde_json::from_str(&key).unwrap();

    assert!(key.strip_secret_material().is_none());
}

#[test]
fn ec_p256_thumbprint() {
    let jwk = read_key_file("p256");
    let jwk: JsonWebKey = serde_json::from_str(&jwk).unwrap();

    let p = jwk.thumbprint_sha256();
    let p = Base64UrlString::encode(p);
    assert_eq!(&*p, "6j1ImYAlN6DnVupozzN13UKnLR7BfEvngNmVl5bLlI0");
}

#[test]
fn rsa_thumbprint() {
    let jwk = read_key_file("rsa");
    let jwk: JsonWebKey = serde_json::from_str(&jwk).unwrap();

    let p = jwk.thumbprint_sha256();
    let p = Base64UrlString::encode(p);
    assert_eq!(&*p, "nYPs6qc5zj3VOVKr4yY-EzirO-AcdUl0JC5bcXKGE6Y");
}

#[test]
fn symmetric_thumbprint() {
    let jwk = json!({
        "k": "FyCq1CKBflh3I5gikEjpYrdOXllzxB_yc02za8ERknI",
        "kty": "oct",
    });

    let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();

    let p = jwk.thumbprint_sha256();
    let p = Base64UrlString::encode(p);
    assert_eq!(&*p, "prDKy90VJzrDTpm8-W2Q_pv_kzrX_zyZ7ANjRAasDxc");
}
