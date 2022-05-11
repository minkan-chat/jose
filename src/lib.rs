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

mod base64;
pub use self::base64::Base64String;

pub mod format;
pub mod jwa;
mod jwe;
mod jwk;
pub mod jws;
mod jwt;

#[doc(inline)]
pub use jwt::JsonWebToken;
