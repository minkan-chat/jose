//! The actual implementations for the cryptographic backends.

pub(super) mod interface;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto-rustcrypto")] {
        mod rust;
        pub(crate) use rust::*;
    } else if #[cfg(feature = "crypto-openssl")] {
        mod openssl;
        pub(crate) use openssl::*;
    } else {
        mod dummy;
        pub(crate) use dummy::*;
    }
}
