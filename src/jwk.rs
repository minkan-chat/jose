#![allow(warnings)]

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonWebKey<T = ()> {
    #[serde(flatten)]
    pub options: CommonKeyOptions,
    #[serde(flatten)]
    pub key: PublicOrPrivateKey,
    #[serde(flatten)]
    pub additional: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommonKeyOptions {
    pub kid: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum PublicOrPrivateKey {
    Public(PublicKey),
    Private(PrivateKey),
}

impl<'de> Deserialize<'de> for PublicOrPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        PrivateKey::deserialize(val.clone())
            .map(|key| Self::Private(key))
            .or_else(|_| PublicKey::deserialize(val).map(|key| Self::Public(key)))
            .map_err(|_| <D::Error as serde::de::Error>::custom("oops"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum PublicKey {
    #[serde(rename = "EC")]
    EllipticCurve(EllipticCurvePublicKey),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum PrivateKey {
    #[serde(rename = "EC")]
    EllipticCurve(EllipticCurvePrivateKey),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EllipticCurvePublicKey {
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EllipticCurvePrivateKey {
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
}
