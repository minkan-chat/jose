//! Common test helpers.

use serde_json::Value;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Reads a key file from the `tests/vectors/jwk` directory.
pub fn read_jwk(name: &str) -> TestResult<Value> {
    let json = std::fs::read_to_string(format!(
        "{}/tests/vectors/jwk/{name}.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?;
    let key: Value = serde_json::from_str(&json)?;

    Ok(key)
}
