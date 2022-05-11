use alloc::vec::Vec;
use core::fmt;

use crate::format::{Compact, Json};

/// This type indicates that the inner value is signed using [signing
/// algorithm].
///
/// [signing algorithm]: crate::jwa::JsonWebSigningAlgorithm
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Signed<F> {
    value: F,
}

impl Signed<Compact> {
    pub(crate) fn new(mut value: Compact, signature: Vec<u8>) -> Self {
        value.push(signature);
        Self { value }
    }
}

impl Signed<Json> {
    pub(crate) fn new(_value: Json, _signature: Vec<u8>) -> Self {
        todo!()
    }
}

impl fmt::Display for Signed<Compact> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, f)
    }
}

impl fmt::Display for Signed<Json> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, f)
    }
}
