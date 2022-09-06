use jose::{header::JwsHeader, jwa::JsonWebSigningAlgorithm};

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

    #[derive(serde::Serialize)]
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

    let header = serde_json::to_string(&header).unwrap();
    assert_eq!(
        r#"{"alg":"EdDSA","b64":true,"crit":["foo","b64"],"foo":true}"#,
        &header
    );
}
