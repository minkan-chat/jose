use super::{JsonWebKey, JsonWebKeyType, KeyUsage};
use crate::jwa::JsonWebAlgorithm;

/// The builder for constructing a [`JsonWebKey`].
#[derive(Debug, Clone)]
pub struct JsonWebKeyBuilder<T> {
    // key_type: JsonWebKeyType,
    // algorithm: Option<JsonWebAlgorithm>,
    _additional: T,
}

impl<T> JsonWebKeyBuilder<T> {
    /// todo
    pub fn build(self) -> Result<JsonWebKey<T>, ()> {
        todo!()
    }
}
