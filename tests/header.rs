use jose::{
    format::Compact,
    header::{HeaderValue, Jws},
    jwa::JsonWebSigningAlgorithm,
    JoseHeader,
};

#[test]
fn build_header() {
    let builder = JoseHeader::<Compact, Jws>::builder();
    let header = builder
        .algorithm(HeaderValue::Protected(JsonWebSigningAlgorithm::None))
        .build()
        .unwrap();
    assert_eq!(
        header.algorithm(),
        HeaderValue::Protected(&JsonWebSigningAlgorithm::None)
    );
}
