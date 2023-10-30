use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{Private, Public, Thumbprint};

/// Some kind of asymmetric cryptographic key which can be either [`Private`] or
/// [`Public`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AsymmetricJsonWebKey {
    /// The private part of an asymmetric key
    Private(Private),
    /// The public part of an asymmetric key
    Public(Public),
}

impl crate::sealed::Sealed for AsymmetricJsonWebKey {}
impl Thumbprint for AsymmetricJsonWebKey {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            AsymmetricJsonWebKey::Private(key) => key.thumbprint_prehashed(),
            AsymmetricJsonWebKey::Public(key) => key.thumbprint_prehashed(),
        }
    }
}

impl From<AsymmetricJsonWebKey> for super::JsonWebKeyType {
    fn from(x: AsymmetricJsonWebKey) -> Self {
        super::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(x))
    }
}
