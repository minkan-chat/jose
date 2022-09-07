use jose::{
    header::{JwsHeader, Protected},
    jwa::JsonWebSigningAlgorithm,
};

#[test]
fn critical_headers() {
    let header = JwsHeader::builder()
        .protected()
        .algorithm(JsonWebSigningAlgorithm::EdDSA)
        .critical_headers(["x5t"].into_iter().map(ToString::to_string))
        .build()
        .expect("forbidden headers are only catched at serialization");

    // yeah that is kinda bad but detecting headers during build time is complicated
    assert!(
        header.critical_headers().any(|h| h == "x5t"),
        "critical headers not checked during build time"
    );
    serde_json::to_string(&header)
        .expect_err("should fail because `x5t` is not allowed to be critical");

    let header = header
        .into_builder()
        .critical_headers(["foo"].into_iter().map(ToString::to_string))
        .build()
        .expect("headers are only checked at serrialization");

    serde_json::to_string(&header)
        .expect_err("should fail because `foo` is not in the actual header");

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Additional {
        foo: bool,
    }
    let header = header
        .into_builder()
        .additional(Additional { foo: true })
        .payload_base64_url_encoded(true)
        .critical_headers(["foo"].into_iter().map(ToString::to_string))
        .build()
        .expect("this is a valid header, foo is critical and included via additional");

    assert_eq!(
        serde_json::from_str::<JwsHeader<Protected, Additional>>(
            r#"{"alg":"EdDSA","b64":true,"crit":["foo","b64"],"foo":true}"#
        )
        .unwrap(),
        header
    );
}

#[test]
fn deserialize_ensure_valid_header() {
    serde_json::from_str::<JwsHeader<Protected>>(
        r#"{"alg":"EdDSA","b64":true,"crit":["foo","b64"]}"#,
    )
    .expect_err("`foo` header is marked as critical but is not part of the header");

    serde_json::from_str::<JwsHeader<Protected>>(
        r#"{"alg":"EdDSA","b64":true,"crit":["foo","b64","alg"],"foo":true}"#,
    )
    .expect_err("`alg` is not allowed to be critical");

    // using serde_json::Value is an easy way to keep all parameters
    let header: JwsHeader<Protected> =
        serde_json::from_str(r#"{"alg":"EdDSA","b64":true,"crit":["foo","b64"],"foo":true}"#)
            .expect("this is valid");
    assert_eq!(
        serde_json::from_str::<JwsHeader<Protected>>(
            r#"{"alg":"EdDSA","b64":true,"crit":["b64","foo"],"foo":true}"#
        )
        .unwrap(),
        header
    );
}
