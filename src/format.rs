//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! Currently, the only two formats are [`Compact`] and [`JsonFlattened`].

mod compact;
mod json_flattened;

use core::fmt;

pub use compact::Compact;
pub use json_flattened::JsonFlattened;

use crate::sealed::Sealed;

pub(crate) mod sealed {
    use core::convert::Infallible;

    use alloc::fmt;

    use crate::{
        header::JoseHeaderBuilderError,
        jws::{PayloadKind, SignError, Signer},
    };

    // We put all methods, types, etc into a sealed trait, so
    // the user is not able to access these thing as they should
    // only be used internally by this crate
    pub trait SealedFormat: Sized {
        type JwsHeader: fmt::Debug;
        type SerializedJwsHeader: fmt::Debug;

        fn update_header<S: AsRef<[u8]>, D: digest::Update>(
            header: Self::JwsHeader,
            signer: &dyn Signer<S, Digest = D>,
        ) -> Result<Self::JwsHeader, JoseHeaderBuilderError>;

        fn provide_header<D: digest::Update>(
            header: Self::JwsHeader,
            digest: &mut D,
        ) -> Result<Self::SerializedJwsHeader, SignError<Infallible>>;

        fn finalize(
            header: Self::SerializedJwsHeader,
            payload: PayloadKind,
            signature: &[u8],
        ) -> Result<Self, serde_json::Error>;
    }
}

/// This trait represents any possible format in which a JWS or JWE can be
/// represented.
pub trait Format: fmt::Display + sealed::SealedFormat + Sized {}

/// to this type.
pub trait DecodeFormat<F>: Sealed + Sized {
    /// The error that can occurr while parsing `Self` from the input.
    type Error;

    /// The decoded type to return.
    type Decoded<T>;

    /// Parse the input into a new [`Decoded`](Self::Decoded) instance of
    /// `Self`.
    ///
    /// # Errors
    ///
    /// Returns an error if the input format has an invalid representation for
    /// this type.
    fn decode(input: F) -> Result<Self::Decoded<Self>, Self::Error>;
}
