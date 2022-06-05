use serde::{Deserialize, Serialize};

use super::{Private, Public};

/// Some kind of asymmetric cryptographic key which can be either [`Private`] or
/// [`Public`]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AsymmetricJsonWebKey {
    /// The private part of an asymmetric key
    Private(Private),
    /// The public part of an asymmetric key
    Public(Public),
}
