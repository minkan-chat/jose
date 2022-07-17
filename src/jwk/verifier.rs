use alloc::string::String;

#[derive(Debug)]
/// An abstract [`Verifier`] over all possible [key types](JsonWebKeyType)
pub struct JwkVerifier {
    _key_id: Option<String>,
}

// /// Abstract type with a variant for each [`Verifier`]
// #[derive(Debug)]
// enum InnerSigner {
// symmetric algorithms
// Hs256(Hs256Verifie),
// Hs384(Hs384Signer),
// Hs512(Hs512Signer),
// asymmetric algorithms
// RSA not implemented yet
// Es256(P256Signer),
// Es384(P384Signer),
// P-512 not supported yet
// Curve-25519 and 448 not supported yet
// }
