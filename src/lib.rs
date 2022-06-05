//! To be written
#![warn(
    missing_docs,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    explicit_outlives_requirements,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc
)]
#![deny(
    rustdoc::broken_intra_doc_links,
    rustdoc::bare_urls,
    macro_use_extern_crate,
    non_ascii_idents,
    elided_lifetimes_in_paths
)]
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod sign;
pub use sign::*;

mod verify;
pub use verify::*;

pub(crate) mod base64_url;
pub(crate) mod borrowable;

pub mod format;
pub mod jwa;
mod jwe;
pub mod jwk;
pub mod jws;
mod jwt;

pub use jws::JsonWebSignature;
pub use jwt::JsonWebToken;

/// Type alias to make `JsonWebSignature` easier to access.
pub type JWS<T, H = ()> = JsonWebSignature<T, H>;

/// Type alias to make `JsonWebToken` easier to access.
pub type JWT = JsonWebToken;
