use std::{env, process::exit};

struct CryptoBackend {
    name: &'static str,
    feature: &'static str,
}

const ALL_BACKENDS: &[CryptoBackend] = &[
    CryptoBackend {
        name: "RustCrypto",
        feature: "crypto-rustcrypto",
    },
    CryptoBackend {
        name: "OpenSSL",
        feature: "crypto-openssl",
    },
    CryptoBackend {
        name: "AWS-LC",
        feature: "crypto-aws-lc",
    },
];

fn main() {
    crypto_backends_check();

    println!("cargo::rustc-check-cfg=cfg(openssl320)");

    // the nonce api for deterministic EcDSA signing is only possible on specific
    // version
    #[expect(clippy::unusual_byte_groupings)]
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=openssl320");
        }
    }
}

fn crypto_backends_check() {
    let enabled = ALL_BACKENDS
        .iter()
        .filter(|backend| {
            std::env::var(format!(
                "CARGO_FEATURE_{}",
                backend.feature.to_uppercase().replace("-", "_")
            ))
            .is_ok()
        })
        .collect::<Vec<_>>();

    if enabled.is_empty() {
        eprintln!(
            "No cryptographic backend selected.

`jose` requires a cryptographic backend.  This backend \
             is selected at compile time using feature flags.

See https://github.com/minkan-chat/jose#crypto-backends\
             "
        );

        exit(1);
    } else if enabled.len() > 1 {
        eprintln!(
            "Multiple cryptographic backends selected.

`jose` requires exactly one cryptographic backend. \
             Unfortunately, you have selected multiple backends:

    {}

See https://github.com/minkan-chat/jose#crypto-backends\
             ",
            enabled
                .iter()
                .map(|b| b.name)
                .collect::<Vec<_>>()
                .join(", ")
        );

        exit(1);
    }
}
