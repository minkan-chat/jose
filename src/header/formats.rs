use crate::{
    format::{Compact, JsonFlattened},
    sealed::Sealed,
};

/// A marker trait for the different serialization formats that can be used in
/// JWS/JWE.
pub trait Format: Sealed {}

impl Format for JsonFlattened {}
impl Format for Compact {}

/// A marker trait used to distinguish between formats with the `header`
/// parameter and serialization formats that only have the `protected` header
/// part (the [`Compact`] form)
pub trait FormatWithUnprotected: Sealed {}
impl FormatWithUnprotected for JsonFlattened {}
