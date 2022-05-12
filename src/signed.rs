use alloc::vec::Vec;
use core::marker::PhantomData;

/// This type indicates that the inner value is signed using [signing
/// algorithm].
///
/// [signing algorithm]: crate::jwa::JsonWebSigningAlgorithm
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Signed<T, F> {
    value: T,
    signature: Vec<u8>,
    _format: PhantomData<F>,
}
