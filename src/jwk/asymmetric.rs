use super::{Private, Public};

/// Some kind of asymmetric cryptographic key which can be either [`Private`] or
/// [`Public`]
#[derive(Debug)]
pub enum AsymmetricJsonWebKey {
    /// The public part of an asymmetric key
    Public(Public),
    /// The private part of an asymmetric key
    Private(Private),
}
