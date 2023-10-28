//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! Currently, the only two formats are [`Compact`] and [`JsonFlattened`].

mod compact;
mod json_flattened;
mod json_general;

use core::fmt;

pub use compact::Compact;
pub use json_flattened::JsonFlattened;
pub use json_general::JsonGeneral;
pub(crate) use json_general::Signature as JsonGeneralSignature;

use crate::sealed::Sealed;

pub(crate) mod sealed {
    use alloc::fmt;
    use core::convert::Infallible;

    use crate::{
        header::{self, JoseHeaderBuilder, JoseHeaderBuilderError},
        jws::{PayloadKind, SignError, Signer},
    };

    // We put all methods, types, etc into a sealed trait, so
    // the user is not able to access these thing as they should
    // only be used internally by this crate
    pub trait SealedFormat<F>: Sized {
        type JwsHeader: fmt::Debug;
        type SerializedJwsHeader: fmt::Debug;

        fn update_header<S: AsRef<[u8]>>(header: &mut Self::JwsHeader, signer: &dyn Signer<S>);

        /// Serializes the header for this format.
        ///
        /// The returned values must be the serializd header and the
        /// bytes that must be appended to the message for the signature.
        fn serialize_header(
            header: Self::JwsHeader,
        ) -> Result<Self::SerializedJwsHeader, SignError<Infallible>>;

        /// This method converts a serialized header into the message bytes
        /// that are used for the signature.
        fn message_from_header(hdr: &Self::SerializedJwsHeader) -> Option<&[u8]>;

        fn finalize(
            header: Self::SerializedJwsHeader,
            payload: PayloadKind,
            signature: &[u8],
        ) -> Result<Self, serde_json::Error>;

        fn finalize_jws_header_builder(
            value_ref: &mut Result<Self::JwsHeader, JoseHeaderBuilderError>,
            new_builder: JoseHeaderBuilder<F, header::Jws>,
        );
    }
}

/// This trait represents any possible format in which a JWS or JWE can be
/// represented.
pub trait Format: fmt::Display + sealed::SealedFormat<Self> + Sized {}

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
