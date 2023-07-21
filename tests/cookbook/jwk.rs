#[rustfmt::skip] // rustfmt is stupid in macros
macro_rules! cookbook_test {
    ($sec:tt $name:ident) => { paste::paste! {
        #[test]
        fn [<_ $sec _ $name:lower>]() -> Result<(), Box<dyn std::error::Error>> {
            use jose::jwk::JsonWebKey;

            let file = format!("tests/cookbook/spec/jwk/{}.{}.json", stringify!($sec), stringify!($name));

            let json = std::fs::read_to_string(file)?;
            let json: serde_json::Value = serde_json::from_str(&json)?;

            let jwk: JsonWebKey = serde_json::from_value(json.clone())?;
            dbg!(&jwk);

            let serialized_jwk = serde_json::to_value(&jwk)?;

            assert_eq!(json, serialized_jwk);

            Ok(())
        }
    }};
}

// not supported because P521 support is missing
// cookbook_test!(3_1 ec_public_key);
// cookbook_test!(3_2 ec_private_key);

cookbook_test!(3_3 rsa_public_key);
cookbook_test!(3_4 rsa_private_key);

cookbook_test!(3_5 symmetric_key_mac_computation);
cookbook_test!(3_6 symmetric_key_encryption);
