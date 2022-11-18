use crate::{
    format::{Compact, JsonFlattened},
    sealed::Sealed,
};

/// A marker trait for the different serialization formats that can be used in
/// JWS/JWE.
pub trait Format: Sealed {}

impl Format for JsonFlattened {}
impl Format for Compact {}
