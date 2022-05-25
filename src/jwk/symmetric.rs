use alloc::vec::Vec;

#[derive(Debug)]
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
pub enum SymmetricJsonWebKey {
    /// `oct` <<https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence {
        /// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
        k: Vec<u8>,
    },
}
