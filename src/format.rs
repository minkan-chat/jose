//! Contains abstractions for different kinds of
//! serialization formats.
//!
//! The formats are [`Compact`], [`JsonFlattened`] and [`JsonGeneral`].

mod compact;
mod json_flattened;
mod json_general;

use core::fmt;

pub use compact::{Compact, CompactJwe, CompactJws};
pub use json_flattened::{JsonFlattened, JsonFlattenedJwe, JsonFlattenedJws};
pub(crate) use json_general::Signature as JsonGeneralSignature;
pub use json_general::{JsonGeneral, JsonGeneralJwe, JsonGeneralJws};

use crate::sealed::Sealed;

pub(crate) mod sealed {
    use alloc::fmt;
    use core::convert::Infallible;

    use crate::{
        header::{self, JoseHeaderBuilder, JoseHeaderBuilderError},
        jws::{PayloadData, SignError, Signer},
    };

    // We put all methods, types, etc into a sealed trait, so
    // the user is not able to access these thing as they should
    // only be used internally by this crate
    pub trait SealedFormatJws<F>: Sized {
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
            payload: Option<PayloadData>,
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
pub trait Format: fmt::Display + sealed::SealedFormatJws<Self> + Sized {}

/// Used to parse a [`Compact`] or another format representation
/// into a concrete type.
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

/// Used to parse a [`Compact`] or another format representation
/// into a concrete type.
pub trait DecodeFormatWithContext<F, C>: Sealed + Sized {
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
    fn decode_with_context(input: F, context: &C) -> Result<Self::Decoded<Self>, Self::Error>;
}

/// A trait to distinguish between
/// [`JsonWebSignature`](crate::JsonWebSignature)s and
/// [`JsonWebEncryption`](crate::JsonWebEncryption) in different serialization
/// [`Format`]s.
///
/// This allows us to reuse types like [`Compact`] across JWS and JWE.
pub trait SealedFormatType: Sealed {
    /// In [`Compact`] serialization, the different parts are base64urlsafe no
    /// pad encoded and then separated by `.`.
    ///
    /// For example, in [`JsonWebSignature`](crate::JsonWebSignature)s, it is
    /// header.payload.signature (all base64urlsafe no pad encoded of course)
    const COMAPCT_PARTS: usize;
}

/// A marker type to represent a [`JsonWebSignature`](crate::JsonWebSignature)
/// in some serialization [`Format`]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Jws {}

impl Sealed for Jws {}
impl SealedFormatType for Jws {
    const COMAPCT_PARTS: usize = 3;
}

/// A marker type to represent a [`JsonWebEncryption`](crate::JsonWebEncryption)
///  in some serialization [`Format`]
#[derive(Debug)]
#[non_exhaustive]
pub struct Jwe {}

impl Sealed for Jwe {}
impl SealedFormatType for Jwe {
    const COMAPCT_PARTS: usize = 5;
}
