//! [`JoseHeader`] and associated abstractions as defined in [section 4 of RFC
//! 7515].
//!
//! [section 4 of RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4>
#![allow(missing_docs)]
use alloc::{collections::BTreeSet, string::String};
use core::{marker::PhantomData, ops::Deref};

use mediatype::{MediaType, MediaTypeBuf};
use serde::Deserialize;
use serde_json::{Map, Value};

mod error;
mod formats;
mod parameters;
mod types;
mod value;

#[doc(inline)]
pub use self::{error::Error, types::*, value::*};
use self::{
    formats::{Format, FormatWithUnprotected},
    parameters::Parameters,
    sealed::NotFoundError,
};
use crate::format::Compact;

#[derive(Debug)]
pub struct JoseHeader<F, T> {
    parameters: Parameters<T>,
    // marker for the format (compact, json general, json flattened)
    _format: PhantomData<F>,
}

impl<T> JoseHeader<Compact, T>
where
    T: Type,
{
    pub fn cty(&self) -> Option<MediaType<'_>> {
        self.parameters.content_type.as_ref().map(|v| {
            v.as_ref()
                .map(|cty| cty.to_ref())
                .protected()
                .expect("only protected headers in compact")
        })
    }
}

impl<F, T> JoseHeader<F, T>
where
    F: Format + FormatWithUnprotected,
    T: Type,
{
    pub fn cty<S: HeaderSecurity>(&self) -> S::Output<MediaType<'_>> {
        match &self.parameters.content_type {
            Some(v) => S::from_value(v.as_ref().map(MediaTypeBuf::to_ref)),
            None => <S::Output<_> as NotFoundError>::not_found(),
        }
    }
}
struct HeaderDeserializer {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl HeaderDeserializer {
    fn from_values(protected: Value, unprotected: Value) -> Result<Self, Error> {
        // The `protected` and `header` parameters must be a JSON Object
        let protected = match protected {
            Value::Object(object) => object,
            _ => return Err(Error::NotAnObject),
        };
        let unprotected = match unprotected {
            Value::Object(object) => object,
            _ => return Err(Error::NotAnObject),
        };

        let protected_keys: BTreeSet<&str> = protected.keys().map(Deref::deref).collect();
        let unprotected_keys: BTreeSet<&str> = unprotected.keys().map(Deref::deref).collect();

        // the members of `protected` and `header` must be disjoint, because otherwise
        // an implementation must decide which header type takes priority
        if !protected_keys.is_disjoint(&unprotected_keys) {
            return Err(Error::NotDisjoint);
        }

        Ok(Self {
            protected,
            unprotected,
        })
    }

    fn deserialize_field<'a, 'de, V>(
        &'a self,
        field: &'a str,
    ) -> Option<Result<HeaderValue<V>, serde_json::Error>>
    where
        V: Deserialize<'de>,
        'a: 'de,
    {
        // Security
        //
        // This method first looks at the `protected` header and if the requested field
        // isn't in there, it looks in the `header` parameter (which is not integrity
        // protected). A `HeaderDeserializer` should always ensure that the inner JSON
        // Object don't share the same parameters but even if they do, an attacker
        // cannot overwrite protected headers via the unprotected header, because the
        // protected header is searched first.

        if let Some(p) = self.protected.get(field) {
            return Some(V::deserialize(p).map(|v| HeaderValue::Protected(v)));
        }

        if let Some(u) = self.unprotected.get(field) {
            return Some(V::deserialize(u).map(|v| HeaderValue::Unprotected(v)));
        }

        None
    }
}
