//! The actual implementations for the cryptographic backends.

pub(super) mod interface;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto-rustcrypto")] {
        mod rust;
        pub(crate) use rust::*;
    } else {
        mod dummy;
        pub(crate) use dummy::*;
    }
}
