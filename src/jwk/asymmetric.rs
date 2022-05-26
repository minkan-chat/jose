use super::{Private, Public};

#[derive(Debug)]
pub enum AsymmetricJsonWebKey {
    /// The public part of an asymmetric key
    Public(Public),
    /// The private part of an asymmetric key
    Private(Private),
}
