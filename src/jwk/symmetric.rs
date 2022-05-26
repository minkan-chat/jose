use alloc::vec::Vec;

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug)]
pub enum SymmetricJsonWebKey {
    /// `oct` <<https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence {
        /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
        k: Vec<u8>,
    },
}
