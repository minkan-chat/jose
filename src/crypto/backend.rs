//! The actual implementations for the cryptographic backends.

pub(super) mod interface;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto-rustcrypto")] {
        mod rust;
        pub(crate) use rust::*;
    } else if #[cfg(feature = "crypto-openssl")] {
        mod openssl;
        pub(crate) use openssl::*;
    } else if #[cfg(feature = "crypto-aws-lc")] {
        mod openssl;
        pub(crate) use openssl::*;
    } else if #[cfg(feature = "crypto-ring")] {
        mod ring;
        pub(crate) use ring::*;
    } else {
        compile_error!("No crypto backend selected. Please enable any of the `crypto-*` features.");
    }
}
