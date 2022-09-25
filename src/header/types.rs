mod jwe;
mod jws;

#[doc(inline)]
pub use self::{jwe::*, jws::*};
use crate::sealed::Sealed;

pub trait Type: Sealed {}

impl Type for Jws {}
impl Type for Jwe {}
