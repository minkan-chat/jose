# **JOSE**: JSON Object Signing and Encryption

JOSE is mostly known for so called [`Jwt`]. Jwt stands for [`JsonWebToken`] and
is actually only a subset of the whole JOSE specifications.

In the majority of cases, [`JsonWebToken`] are a signed token that act as small
certificates for authentication. However, JOSE is way more complex than just a
simple signed certificate.

Because of this complexity, most implementation are incomplete. Even worse, bad
library design often lead to critical security vulnerabilities, such as the
famous [`none` Algorithm bug][1].

In order to prevent such vulnerabilities, this crate uses the Rust type system
to make illegal states impossible and marks insecure or unverified /! states
directly on the types themselves.

# Example

## Create a basic [`Jwt`]

In this crate, cryptographic keys are always represented as a type, never as a
[`String`] or some other format that would lose essential information about a
key, such as its [algorithm](crate::jwa::JsonWebAlgorithm).

One should usually use the [`JsonWebKey`] type, because it abstracts away the
complexity of different key types. Your application should not care what kind of
key it gets.

```rust
extern crate alloc;
use alloc::string::ToString;

use jose::{
    format::{Compact, DecodeFormat},
    jwk::{JwkSigner, JwkVerifier},
    jws::Unverified,
    jwt::Claims,
    policy::{Checkable, StandardPolicy},
    JsonWebKey, Jwk, Jwt, UntypedAdditionalProperties,
};


// This is a serialized asymmetric key. The private key part is stored in
// the `d` parameter
let serialized_private_key = r#"
{
    "crv": "P-256",
    "kty": "EC",
     "x": "1uiXGPoQ3eLR3VOsCfnx1YzIJZGUQLbVfbl1CpCHcs0",
     "y": "danaoyQqKi48vlB2jnCoFmq3PdIbYwIRJyNKWiindZM",
     "d": "eLGzm5zd242okyN9SQBvmaC_4EPvASCgMhFgwtBvf3k",
     "alg": "ES256"
}
"#;
let private_key: JsonWebKey = serde_json::from_str(serialized_private_key).expect("valid key");
// A JsonWebToken is just a specific version of a JsonWebSignature where
// the payload is defined as a JSON Object
// This JSON Object is easiest represented by the Claims struct of this crate.
// UntypedAdditionalProperties is used to keep any members of the JSON Object
// that are not directly handled in this implementation.
let claims: Claims<UntypedAdditionalProperties> = Claims {
    subject: Some("Erik".to_string()),
    issuer: Some("AuthenticationProvider".to_string()),
    // sets the rest to None
    ..Default::default()
};
// because the key has the private component, it is able to create signatures
assert!(private_key.is_signing_key());
// A policy is used to ensure a key uses secure algorithm, key size etc.
let policy = StandardPolicy::default();
// a signer can create signatures
let mut signer: JwkSigner = private_key
    .check(&policy)
    .expect("valid key")
    .try_into()
    .expect("key has algorithm");
let jwt = Jwt::builder_jwt().build(claims).expect("header valid");
// this creates a signed JWT that can be serialized.
let signed_jwt = jwt.sign(&mut signer).unwrap();
let serialized = signed_jwt.to_string();

// Note: not all signatures are deterministic, meaning their signature is
// not always the same. That's why we only check the first part here
assert!(
    serialized.starts_with("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJBdXRoZW50aWNhdGlvblByb3ZpZGVyIiwic3ViIjoiRXJpayJ9.")
);

// The serialized public key. Note the missing `d` parameter
let serialized_public_key = r#"
{
    "crv": "P-256",
    "kty": "EC",
     "x": "1uiXGPoQ3eLR3VOsCfnx1YzIJZGUQLbVfbl1CpCHcs0",
     "y": "danaoyQqKi48vlB2jnCoFmq3PdIbYwIRJyNKWiindZM",
     "alg": "ES256"
}
"#;

let public_key: Jwk = serde_json::from_str(&serialized_public_key).unwrap();

// This key can only verify signatures
assert_eq!(public_key.is_signing_key(), false);

let mut verifier: JwkVerifier = public_key
    .check(&policy)
    .unwrap()
    .try_into()
    .unwrap();

// deserialize the JWT
let encoded: Compact = serialized.parse().expect("valid format");

// decode the JWT
// Note: this JWT is not yet verified!
let unverified: Unverified<Jwt<UntypedAdditionalProperties>> =
    Jwt::decode(encoded).expect("valid JWT");

// now the JWT is verified and we can trust the payload
let verified = unverified.verify(&mut verifier).expect("valid signature");
assert_eq!(verified.payload().subject, Some("Erik".to_string()));
```

This crate implements various RFCs related to JOSE:

- [RFC 7519]: JSON Web Token (JWT)
- [RFC 7518]: JSON Web Algorithms (JWA)
- [RFC 7517]: JSON Web Key (JWK)
- ~~[RFC 7516]: JSON Web Encryption (JWE)~~ (Encryption is not supported in this
  first release)
- [RFC 7515]: JSON Web Signature (JWS)

[1]: <https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>
[RFC 7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
[RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518>
[RFC 7517]: <https://datatracker.ietf.org/doc/html/rfc7517>
[RFC 7516]: <https://datatracker.ietf.org/doc/html/rfc7516>
[RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>
[`Jwt`]: <https://docs.rs/jose/latest/jose/type.Jwt.html>
[`JsonWebToken`]: <https://docs.rs/jose/latest/jose/type.JsonWebToken.html>
[`JsonWebKey`]: <https://docs.rs/jose/latest/jose/struct.JsonWebKey.html>
[`String`]: <https://doc.rust-lang.org/nightly/std/string/struct.String.html>

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0)>
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
