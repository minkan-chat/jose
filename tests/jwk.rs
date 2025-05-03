use jose::{
    crypto::hmac,
    jwa::{self, JsonWebAlgorithm},
    jwk::{self, policy::Checkable, FromKey as _, Thumbprint as _},
    Base64UrlString, JsonWebKey,
};
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

use crate::common::{read_jwk, TestResult};

mod common;

fn roundtrip(file: &str, unsupported: bool, check: fn(&JsonWebKey)) -> TestResult {
    let mut json_key = read_jwk(file)?;
    let json_key_str = serde_json::to_string(&json_key)?;

    let jwk = match serde_json::from_value::<JsonWebKey>(json_key.clone()) {
        Ok(..) if unsupported => panic!("Unsupported key type was successful"),
        Ok(jwk) => jwk,
        Err(..) if unsupported => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    check(&jwk);

    // we want to deserialize the JWK from an owned value, and a borrowed value
    let jwk_from_str = serde_json::from_str::<JsonWebKey>(&json_key_str)?;
    assert_eq!(jwk.key_type(), jwk_from_str.key_type());

    let mut serialized = serde_json::to_value(&jwk)?;
    let mut serialized_from_str = serde_json::to_value(&jwk_from_str)?;

    // removes the field `name` from the given json value, mostly because some
    // fields are serialized non-deterministic (key_ops), because the order is
    // random
    let remove_field = |value: &mut serde_json::Value, name: &str| {
        if let Some(obj) = value.as_object_mut() {
            obj.remove(name);
        }
    };

    let mut remove_field_from_all = |name: &str| {
        remove_field(&mut json_key, name);
        remove_field(&mut serialized, name);
        remove_field(&mut serialized_from_str, name);
    };

    remove_field_from_all("key_ops");

    assert_eq!(json_key, serialized);
    assert_eq!(json_key, serialized_from_str);

    // now try constructing a builder using this key, and check invalid
    // algorithm
    let err = JsonWebKey::builder(jwk.key_type().clone())
        .algorithm(Some(JsonWebAlgorithm::Other("foo".to_string())))
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        jwk::JsonWebKeyBuildError::IncompatibleKeyType
    ));

    let err = jwk
        .into_builder()
        .algorithm(Some(JsonWebAlgorithm::Other("foo".to_string())))
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        jwk::JsonWebKeyBuildError::IncompatibleKeyType
    ));

    Ok(())
}

fn roundtrip_pair(
    private: &str,
    public: &str,
    unsupported: bool,
    check: fn(&JsonWebKey),
) -> TestResult {
    roundtrip(private, unsupported, check)?;
    roundtrip(public, unsupported, check)?;

    if unsupported {
        return Ok(());
    }

    let private_key: JsonWebKey = serde_json::from_value(read_jwk(private)?)?;
    let public_key: JsonWebKey = serde_json::from_value(read_jwk(public)?)?;

    assert!(private_key.is_signing_key());
    assert!(!public_key.is_signing_key());

    assert!(!private_key.is_symmetric());
    assert!(!public_key.is_symmetric());

    assert!(private_key.is_asymmetric());
    assert!(public_key.is_asymmetric());

    let stripped = private_key.clone().strip_secret_material().unwrap();
    assert_eq!(stripped.key_type(), public_key.key_type());

    let stripped_from_public = public_key.clone().strip_secret_material().unwrap();
    assert_eq!(stripped_from_public.key_type(), public_key.key_type());

    let into_verifying = private_key.into_verifying_key();
    assert_eq!(into_verifying.key_type(), public_key.key_type());

    let public_into_verifying = public_key.clone().into_verifying_key();
    assert_eq!(public_into_verifying.key_type(), public_key.key_type());

    Ok(())
}

fn assert_thumbprint(jwk: &JsonWebKey, sha256: &str, sha384: &str, sha512: &str) {
    let print_sha256 = Base64UrlString::encode(jwk.thumbprint_sha256());
    assert_eq!(&*print_sha256, sha256);

    let print_sha384 = Base64UrlString::encode(jwk.thumbprint_sha384());
    assert_eq!(&*print_sha384, sha384);

    let print_sha512 = Base64UrlString::encode(jwk.thumbprint_sha512());
    assert_eq!(&*print_sha512, sha512);
}

pub mod roundtrip {
    use jose::{jwa, jwk};
    use pretty_assertions::assert_eq;

    use crate::{assert_thumbprint, common::TestResult, roundtrip, roundtrip_pair};

    #[test]
    fn _3_1_and_2_ec() -> TestResult {
        roundtrip_pair(
            "3_2.ec_private_key",
            "3_1.ec_public_key",
            // RustCrypto and ring do not support P-521 curve
            cfg!(feature = "crypto-rustcrypto") || cfg!(feature = "crypto-ring"),
            |jwk| {
                assert_eq!(jwk.key_usage(), Some(&jwk::KeyUsage::Signing));
                assert_thumbprint(
                    jwk,
                    "dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M",
                    "HncTFMje-quVjjwt2ufqfFb75ZwHLDh9M-VY4wJ9awQkfbu194TmVpeGbG6Ykb9b",
                    "i8RIsIb6HVP2AO9o38HtraybJAP5veAfBIgynNUqpxlhuvq2UDgSA3JFgGgle1YvmCQDHllAn7MG52Idb8B4fA"
                );
            },
        )
    }

    #[test]
    fn _3_3_and_4_rsa() -> TestResult {
        roundtrip_pair("3_4.rsa_private_key", "3_3.rsa_public_key", false, |jwk| {
            assert_thumbprint(
                jwk,
                "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI",
                "iRBthSmwxk6o9pTGF6a9yLHohmMXSFRvKoN9rgcbOWFgLldwqED1DrOgDtLq5Q4R",
                "FerGBUpYnzT0ptNAC7Y3qNpGINqILXdZ_9-Na3UkPUtDznnAChw7NWluNRjx-lmKDnuO1CpmIZL7e2bzRkQBew",
            );
        })
    }

    #[test]
    fn _3_5_symmetric_key_mac() -> TestResult {
        roundtrip("3_5.symmetric_key_mac_computation", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::Hmac::Hs256))
            );

            assert!(jwk.is_symmetric());
            assert!(jwk.is_signing_key());

            assert_eq!(jwk.key_type(), jwk.clone().into_verifying_key().key_type());

            assert_thumbprint(
                jwk,
                "RtoRur_1Dir5M4wuOfqNkDYOf9O_4RJ-aHkTA75RLA8",
                "KG7sBEFjGfsIG21uR9cggZfOEIdKSvylcD7ndWgQsnG2k_5Wpw700r__c63SBBwf",
                "EI4XUPoajddrVSS3fgSS6AcPt1uuacMmuYIi9i4A2CgjnWHuUV1qyNks84w03blKdF75HPSTJTJWgqRNEU_ZIg"
            );
        })
    }

    #[test]
    fn _3_6_symmetric_key_encryption() -> TestResult {
        roundtrip("3_6.symmetric_key_encryption", false, |jwk| {
            // NOTE: We do not support A256GCM as a JWK, because it's a one-time use
            // session key, and must not be stored or reused
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::Other("A256GCM".to_string()))
            );
            assert_eq!(jwk.key_usage(), Some(&jwk::KeyUsage::Encryption));

            assert_thumbprint(
                jwk,
                "VDMp1ZgGGv1OKgOeDc1EUKHXNQzMdLkCnxPETHdA4v0",
                "4YmDfp3zlozmoDxrRxpMBiU6XHA9X82IKNW3bWiitdnudrwmAiKOi4yWWj4fyeYm",
                "FmHGxbagOqt0LS__rv4hIpgnQ9pAB7nDneYNPN9i1gHIbvJJILw-VyyYIP_RTgsOU7K683SdE5aeplCUqz4ZaA"
            );
        })
    }

    #[test]
    fn ed25519() -> TestResult {
        roundtrip_pair("ed25519", "ed25519.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(
                    jwa::JsonWebSigningAlgorithm::EdDSA
                ))
            );

            assert_thumbprint(
                jwk,
                "IpNACexNZWO9hVeADtTT0Nvturu6OtMV3B4u1OVr1fU",
                "NibgvGWph4nhazrZ1PcyRXYy55bdTotSDi1L4iE8gB0VtxDhh_a-du0fSnGExFwa",
                "uS4j-x1iQUeF2a4a7M3iHZhPQGwyKgXU2Fh_GeNn9_uw_KAj1VTmNVenxTiFdDqcDHoWBemcLjioFY4slFbIZA",
            );
        })
    }

    #[test]
    fn rsa_enc_optional_parameters() -> TestResult {
        roundtrip("jwk_optional_parameters_rsa_enc.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::RsaesOaep::RsaesOaep))
            );

            assert_eq!(jwk.key_usage(), Some(&jwk::KeyUsage::Encryption));
            assert!(jwk.x509_certificate_sha1_thumbprint().is_some());
            assert!(jwk.x509_certificate_sha256_thumbprint().is_some());

            assert_thumbprint(
                jwk,
                "ZwmJSHbFy5nl7WenHepIG5N9Rz16NH8SPGeqoZPTTuc",
                "06f-mujFCZ0cUPKCgm0m7EuE0TW2mUmoQ0I519rD73v5JDAWti5QsuOX2PqTYuhV",
                "EaW6WfYvQ5rauUmOYPZi82-ADGjmOb3Jz76jNVHUIQ_vA42s7CFve47jVTyb1n3UQbqLw3DDguD4u0wlFL4sbg"
            );
        })
    }

    #[test]
    fn rsa_sign_optional_parameters() -> TestResult {
        roundtrip("jwk_optional_parameters_rsa_sig.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::RsassaPkcs1V1_5::Rs256))
            );

            assert_eq!(jwk.key_usage(), Some(&jwk::KeyUsage::Signing));
            assert!(jwk.x509_certificate_sha1_thumbprint().is_some());
            assert!(jwk.x509_certificate_sha256_thumbprint().is_some());

            assert_thumbprint(
                jwk,
                "bVeakRIe7OjtcR6E5FfkZvFAhEXfhIboYrcZ7OhZ1UY",
                "_jnSoeQaW04m5PzXFnP7w2Zl_WFEop1UEKZ2vGHtQCdfsSqOkLhTbn2vyaDcMbHQ",
                "cHiM1PMNsVve19_e5cfCiJqIMnQhYx0CkcvmiNCdwulCJ5B5ftaAvFYwr7_NQCMTQeXMcTKdbsP2a4mEKojPaQ"
            );
        })
    }

    #[test]
    fn rsa_with_key_ops_for_enc() -> TestResult {
        roundtrip("key_ops_rsa_enc.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::RsaesOaep::RsaesOaep))
            );

            let ops = jwk.key_operations().unwrap();

            assert_eq!(ops.len(), 2);
            assert!(ops.contains(&jwk::KeyOperation::Encrypt));
            assert!(ops.contains(&jwk::KeyOperation::Decrypt));

            assert_eq!(jwk.key_usage(), Some(&jwk::KeyUsage::Encryption));

            assert_thumbprint(
                jwk,
                "ZwmJSHbFy5nl7WenHepIG5N9Rz16NH8SPGeqoZPTTuc",
                "06f-mujFCZ0cUPKCgm0m7EuE0TW2mUmoQ0I519rD73v5JDAWti5QsuOX2PqTYuhV",
                "EaW6WfYvQ5rauUmOYPZi82-ADGjmOb3Jz76jNVHUIQ_vA42s7CFve47jVTyb1n3UQbqLw3DDguD4u0wlFL4sbg"
            );
        })
    }

    #[test]
    fn p256() -> TestResult {
        roundtrip_pair("p256", "p256.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::EcDSA::Es256))
            );

            assert_thumbprint(
                jwk,
                "6j1ImYAlN6DnVupozzN13UKnLR7BfEvngNmVl5bLlI0",
                "u5W5WvG_wZc2u18HY0hqP48hVOOwytBz3BZzBimJl43SA3A4l-INFnhMNLEWL8a3",
                "8fmi-z_V-FykWlKQAscDYj3I_uonEd2-0ChLqb7BwRJqnQiitQ9widx6Pk9ewMkhFk8NnBr1hCFa51kyrg7Pyw"
            );
        })
    }

    #[test]
    fn p384() -> TestResult {
        roundtrip_pair("p384", "p384.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::EcDSA::Es384))
            );

            assert_thumbprint(
                jwk,
                "B_9VooM6jEuy9OvK_plFUDVADfKKnjCUPrqfc5Wtgq4",
                "TXXx3K1KOHjCKWt_bY9cFZfsI9E8NUw8sK1xSOfd0jVgaBMiCP1hFvsxaamAQfK5",
                "AtsWpt8bdnsqT49ovBfv67rhq_PB2eqnhvJ4F-uH-STeCZTVO97hWeEc0zGoOT18XtmHf_2o6ENmwIv9gcXyRQ"
            );
        })
    }

    #[test]
    #[cfg_attr(feature = "crypto-ring", ignore)]
    fn secp256k1() -> TestResult {
        roundtrip_pair("k256", "k256.pub", false, |jwk| {
            assert_eq!(
                jwk.algorithm(),
                Some(&jwa::JsonWebAlgorithm::from(jwa::EcDSA::Es256K))
            );

            assert_thumbprint(
                jwk,
                "i0H0zy_Zyc4g9gUfIU3ZgSk21eC_a9B-J_keq5eRVq4",
                "NWo1frAmwhk6vYKYK0YCTpJWbgvI-EDV5ZvEFvA_7V4y6VRAG0l4Q_uNkFIiisuL",
                "E1oJ78FUrNMsq66wi7AT8jIU4QUMoV_JnYiCqwy2vgDod7yDHMXLkweJ0Vhd1A1TJysPMFNr4Q8yVvQ4Q1fXKg"
            );
        })
    }

    #[test]
    fn rsa() -> TestResult {
        roundtrip_pair("rsa", "rsa.pub", false, |jwk| {
            assert_thumbprint(
                jwk,
                "nYPs6qc5zj3VOVKr4yY-EzirO-AcdUl0JC5bcXKGE6Y",
                "JhX_riWIrTLs3p7SnueDgpcO27pDgXh1xQOivPzOKsU3CaQgHoLgiKIinmb2CMoE",
                "DQd_FsR8hTwlVrv3WGQP2E1KQejcBbJCFtqWy489xmmPm8LdNT91zYFX-yTghCtq2zutBGYY2mkwIWN-VQWYyQ"
            );
        })
    }

    #[test]
    #[cfg_attr(
        any(
            feature = "crypto-ring",
            feature = "crypto-aws-lc",
            feature = "crypto-rustcrypto"
        ),
        ignore
    )]
    fn ed448() -> TestResult {
        roundtrip_pair("ed448", "ed448.pub", false, |jwk| {
            assert_thumbprint(
                jwk,
                "-K8d13H2SA_vuRYSxn05sQN4hAkeWXFt5XainSnkfZc",
                "a_AWZk_w5qSm2XziCOKyHRLU1amUzTlbb1df8Q0JCx3bOaQp0YcLqdHS2Sbyw2PQ",
                "qM1ai1zIZ-NRzbkOKxVkOY6DXVXmDWsSXMCQRRy7oIZEwRzQ0gQK5c-cruMkpyYcBs7ftQcofV_YXWfCdKhSWw",
            );
        })
    }
}

// TODO: test to ensure correct length of x, y, d

#[test]
fn deny_duplicates_key_operations() {
    let key = r#"
{
    "key_ops": ["encrypt", "decrypt", "encrypt"],
    "kty": "oct",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
}
"#;

    serde_json::from_str::<JsonWebKey>(key).unwrap_err();
}

#[test]
fn deny_hmac_key_with_short_key() -> TestResult {
    let raw_key = r#"{"kty": "oct", "k": "QUFBQQ"}"#;
    let key = serde_json::from_str::<jwk::symmetric::OctetSequence>(raw_key)?;

    let hmac = hmac::Key::<hmac::Hs256>::from_key(&key, jwa::Hmac::Hs256.into());

    assert!(matches!(
        hmac.unwrap_err(),
        jwk::symmetric::FromOctetSequenceError::InvalidLength
    ));

    Ok(())
}

pub mod generate {
    use jose::{
        crypto::{
            ec::{P256PrivateKey, P384PrivateKey, P521PrivateKey},
            hmac, okp, rsa,
        },
        jwk::Thumbprint as _,
    };

    use crate::common::TestResult;

    #[test]
    #[cfg_attr(feature = "crypto-ring", ignore)]
    fn ec_p256() -> TestResult {
        let p256 = P256PrivateKey::generate()?;
        let p256_pub = p256.to_public_key();
        assert_eq!(p256.thumbprint_sha256(), p256_pub.thumbprint_sha256());

        Ok(())
    }

    #[test]
    #[cfg_attr(feature = "crypto-ring", ignore)]
    fn ec_p384() -> TestResult {
        let p384 = P384PrivateKey::generate()?;
        let p384_pub = p384.to_public_key();
        assert_eq!(p384.thumbprint_sha256(), p384_pub.thumbprint_sha256());

        Ok(())
    }

    #[test]
    #[cfg_attr(any(feature = "crypto-rustcrypto", feature = "crypto-ring"), ignore)]
    fn ec_p521() -> TestResult {
        let p521 = P521PrivateKey::generate()?;
        let p521_pub = p521.to_public_key();
        assert_eq!(p521.thumbprint_sha256(), p521_pub.thumbprint_sha256());

        Ok(())
    }

    #[test]
    #[cfg_attr(feature = "crypto-ring", ignore)]
    fn rsa() -> TestResult {
        let rsa = rsa::PrivateKey::generate(4096)?;
        let rsa_pub = rsa.to_public_key();
        assert_eq!(rsa.thumbprint_sha256(), rsa_pub.thumbprint_sha256());

        Ok(())
    }

    #[test]
    fn hmac() -> TestResult {
        let _hmac = hmac::Key::<hmac::Hs256>::generate()?;
        Ok(())
    }

    #[test]
    #[cfg_attr(feature = "crypto-ring", ignore)]
    fn ed25519() -> TestResult {
        let ed25519 = okp::PrivateKey::<okp::Ed25519>::generate()?;
        let ed25519_pub = ed25519.to_public_key();
        assert_eq!(ed25519.thumbprint_sha256(), ed25519_pub.thumbprint_sha256());

        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(
            feature = "crypto-rustcrypto",
            feature = "crypto-ring",
            feature = "crypto-aws-lc"
        ),
        ignore
    )]
    fn ed448() -> TestResult {
        let ed448 = okp::PrivateKey::<okp::Ed448>::generate()?;
        let ed448_pub = ed448.to_public_key();
        assert_eq!(ed448.thumbprint_sha256(), ed448_pub.thumbprint_sha256());

        Ok(())
    }
}

#[test]
fn convert_to_public_key() -> TestResult {
    let private_json = read_jwk("p256")?;
    let public_json = read_jwk("p256.pub")?;

    let private: JsonWebKey = serde_json::from_value(private_json)?;
    let public: JsonWebKey = serde_json::from_value(public_json)?;

    let public_converted = private.clone().into_verifying_key();
    assert_eq!(public.key_type(), public_converted.key_type());

    let public_converted = private.strip_secret_material().unwrap();
    assert_eq!(public.key_type(), public_converted.key_type());

    Ok(())
}

#[test]
fn symmetric_key_can_not_strip_secret() -> TestResult {
    let key = read_jwk("3_5.symmetric_key_mac_computation")?;
    let key: JsonWebKey = serde_json::from_value(key)?;
    assert!(key.strip_secret_material().is_none());

    Ok(())
}

#[test]
fn additional_properties() -> TestResult {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Additional {
        #[serde(rename = "additional/one")]
        one: String,
        another_additional: i32,
    }

    impl Checkable for Additional {
        fn check<P: jwk::policy::Policy>(
            self,
            policy: P,
        ) -> Result<jwk::policy::Checked<Self, P>, (Self, P::Error)> {
            Ok(jwk::policy::Checked::new(self, policy))
        }
    }

    let key = read_jwk("rsa_with_additional_props.pub")?;
    let key: JsonWebKey<Additional> = serde_json::from_value(key)?;

    assert_eq!(key.additional().one.as_str(), "my rsa key");
    assert_eq!(key.additional().another_additional, 1);

    let untyped = key.clone().into_untyped_additional()?;
    assert_eq!(
        untyped
            .clone()
            .deserialize_additional::<Additional>()?
            .additional(),
        key.additional()
    );

    let untyped = untyped.additional();

    assert_eq!(untyped["additional/one"], "my rsa key");
    assert_eq!(untyped["another_additional"], 1);

    let _checked = key.check(jwk::policy::StandardPolicy::new()).unwrap();

    Ok(())
}
