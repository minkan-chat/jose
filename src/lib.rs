//! To be written
#![warn(
    missing_docs,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    explicit_outlives_requirements,
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
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "std", allow(unused_qualifications))]

extern crate alloc;

#[macro_use]
mod macros;

pub(crate) mod base64_url;
#[macro_use]
pub(crate) mod tagged_visitor;
pub(crate) mod sealed;

pub mod format;
pub mod header;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;
mod jwt;
pub mod policy;
mod uri;

use alloc::string::String;

pub use base64_url::Base64UrlString;
pub use uri::Uri;

#[doc(inline)]
pub use self::{header::JoseHeader, jwk::JsonWebKey, jws::JsonWebSignature, jwt::JsonWebToken};

/// Type alias to make [`JsonWebSignature`] easier to access.
pub type Jws<F = format::Compact, T = ()> = JsonWebSignature<F, T>;

/// Type alias to make [`JsonWebToken`] easier to access.
pub type Jwt<A = ()> = JsonWebToken<A>;

/// Type alias to make [`JsonWebKey`] easier to access.
pub type Jwk<A = ()> = JsonWebKey<A>;

/// This type is used when the type of the additional parameters
/// of a [`JsonWebKey`], or a [`JoseHeader`] can not be
/// specified, but must not be discarded.
pub type UntypedAdditionalProperties = serde_json::Map<String, serde_json::Value>;
