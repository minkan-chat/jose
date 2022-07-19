/// A trait to protect traits meant only to be implemented by types from this
/// crate from types outside this crate ([`C-SEALED`])
///
/// [`C-SEALED`]: <https://rust-lang.github.io/api-guidelines/future-proofing.html>
pub trait Sealed {}
