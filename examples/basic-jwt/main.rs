//! Simple program to generate, sign and verify a JsonWebToken (JWT)

use clap::Parser;
use clio::Input;
use eyre::eyre;
use jose::{
    format::{Compact, DecodeFormat},
    jwk::{
        ec::p256::P256PrivateKey,
        symmetric::hmac::{HmacKey, Hs256},
        IntoJsonWebKey, JwkSigner, JwkVerifier, KeyOperation,
    },
    jwt::Claims,
    policy::{Checkable, StandardPolicy},
    JsonWebKey, Jwt,
};
use rand::rngs::ThreadRng;
use serde_json::Value;

#[derive(Parser)]
enum Commands {
    /// Generates a JsonWebKey
    Generate {
        /// Wheter or not it should be a symmetric secret or not
        #[arg(short, long)]
        symmetric: bool,
    },
    /// Signs a payload with a JsonWebKey
    Sign {
        /// Key used to sign the JsonWebToken
        key: Input,
        /// The claims that this JWT should contain
        payload: Input,
    },
    /// Verifies a JsonWebToken with a JsonWebKey
    Verify { jwt: String, key: Input },
}

fn main() -> eyre::Result<()> {
    let cmds = Commands::parse();

    match cmds {
        Commands::Generate { symmetric } => {
            let key = match symmetric {
                true => HmacKey::<Hs256>::generate(ThreadRng::default())
                    .into_jwk(Some(()))
                    .expect("Infallible"),
                false => P256PrivateKey::generate(&mut ThreadRng::default())
                    .into_jwk(Some(()))
                    .expect("Infallible"),
            };
            // Key containing private/secret key
            let private_key = key
                .into_builder()
                .key_operations(Some([KeyOperation::Sign, KeyOperation::Verify]))
                .build()?;
            println!("Private:\n{}", serde_json::to_string(&private_key)?);

            // If the key can be made public, do so and print it as well
            if let Some(public) = private_key.strip_secret_material() {
                println!("Public:\n:{}", serde_json::to_string(&public)?)
            };
        }
        Commands::Sign { key, payload } => {
            let key: JsonWebKey = serde_json::from_reader(key)?;
            // use serde_json::Value to keep all values in the payload
            let payload: Claims<serde_json::Value> = serde_json::from_reader(payload)?;
            if !key.is_signing_key() {
                return Err(eyre!("Key is not capable of signing"));
            }

            let key = key
                .check(StandardPolicy::default())
                .map_err(|(_key, e)| e)?;
            let mut signer: JwkSigner = key.try_into()?;

            let jwt = Jwt::builder_jwt().build(payload)?;
            let signed = jwt.sign(&mut signer)?;
            let encoded = signed.encode();
            println!("JWT: {encoded}");
        }
        Commands::Verify { jwt, key } => {
            let key: JsonWebKey = serde_json::from_reader(key)?;
            let key = key.check(StandardPolicy::default()).map_err(|(_, e)| e)?;
            let mut verifier: JwkVerifier = key.try_into()?;
            let encoded: Compact = jwt.parse()?;
            let unverified_jwt = Jwt::<Value>::decode(encoded)?;
            let jwt = unverified_jwt.verify(&mut verifier)?;
            let payload = jwt.payload();
            println!(
                "JWT: Sub {:?}, {:?}:",
                payload.subject,
                payload.additional.get("name")
            )
        }
    }
    Ok(())
}
