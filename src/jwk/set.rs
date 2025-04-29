//! This module contains the JWK Set implementation.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{
    policy::{Checkable, Checked, Policy},
    FromJwkError, JsonWebKey, JwkSigner, JwkVerifier,
};

/// A list of raw [`JsonWebKey`] objects, which is parsed according to [Section
/// 5 of RFC 7517](https://www.rfc-editor.org/rfc/rfc7517#section-5).
///
/// ## Additional parameters
///
/// The `A` type parameter can be used to specify additional parameters for all
/// the json web keys inside this set.
///
/// ## Use key set for operations
///
/// In order to use a key set for signing or verifying, you first have to
/// validate all keys inside the set. Similar to how to have to check a
/// [`JsonWebKey`] in order to get a [`Signer`] or [`Verifier`] instance.
///
/// [`Signer`]: crate::jws::Signer
/// [`Verifier`]: crate::jws::Verifier
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct JsonWebKeySet<A = ()> {
    keys: Vec<JsonWebKey<A>>,
}

impl<A> JsonWebKeySet<A> {
    /// Tries to find the JWK with the given key ID paramter set.
    pub fn find_by_keyid(&self, key_id: &str) -> Option<&JsonWebKey<A>> {
        self.keys
            .iter()
            .find(|key| key.key_id().is_some_and(|id| id == key_id))
    }

    /// Returns an iterator over all the JWKs in this set.
    pub fn iter(&self) -> impl Iterator<Item = &JsonWebKey<A>> {
        self.keys.iter()
    }

    /// Returns an iterator that allows modifying each JWK.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut JsonWebKey<A>> {
        self.keys.iter_mut()
    }

    /// Checks all keys inside this set using the given policy.
    ///
    /// ## Errors
    ///
    /// If any of the keys inside this set do not pass the policy check, this
    /// function will return an error.
    pub fn check<P: Policy + Clone>(self, policy: P) -> Result<CheckedJsonWebKeySet<P, A>, P::Error>
    where
        A: Checkable,
    {
        let mut validated = Vec::new();

        for key in self.keys {
            match key.check(policy.clone()) {
                Ok(checked) => validated.push(checked),
                Err((_, err)) => return Err(err),
            }
        }

        Ok(CheckedJsonWebKeySet { keys: validated })
    }
}

impl<'a, A> IntoIterator for &'a mut JsonWebKeySet<A> {
    type IntoIter = core::slice::IterMut<'a, JsonWebKey<A>>;
    type Item = &'a mut JsonWebKey<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter_mut()
    }
}

impl<'a, A> IntoIterator for &'a JsonWebKeySet<A> {
    type IntoIter = core::slice::Iter<'a, JsonWebKey<A>>;
    type Item = &'a JsonWebKey<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

impl<A> IntoIterator for JsonWebKeySet<A> {
    type IntoIter = alloc::vec::IntoIter<Self::Item>;
    type Item = JsonWebKey<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.into_iter()
    }
}

impl<A> From<Vec<JsonWebKey<A>>> for JsonWebKeySet<A> {
    fn from(keys: Vec<JsonWebKey<A>>) -> Self {
        Self { keys }
    }
}

impl<A> FromIterator<JsonWebKey<A>> for JsonWebKeySet<A> {
    fn from_iter<T: IntoIterator<Item = JsonWebKey<A>>>(iter: T) -> Self {
        let keys = iter.into_iter().collect();
        Self { keys }
    }
}

impl<A, P: Policy> From<CheckedJsonWebKeySet<P, A>> for JsonWebKeySet<A> {
    fn from(checked: CheckedJsonWebKeySet<P, A>) -> Self {
        checked.into_jwk_set()
    }
}

/// A list of validated [`JsonWebKey`] objects.
///
/// This is the version of a [`JsonWebKeySet`] whose keys have all been checked,
/// so it is safe now to use them for signing or verifying data.
#[derive(Debug, Default, Clone)]
pub struct CheckedJsonWebKeySet<P, A = ()> {
    keys: Vec<Checked<JsonWebKey<A>, P>>,
}

impl<A, P: Policy> CheckedJsonWebKeySet<P, A> {
    /// Converts this checked JWK set back into a normal [`JsonWebKeySet`].
    pub fn into_jwk_set(self) -> JsonWebKeySet<A> {
        let keys = self
            .keys
            .into_iter()
            .map(|x| x.into_type())
            .collect::<Vec<_>>();

        JsonWebKeySet { keys }
    }

    /// Tries to convert all keys in this set to [`JwkSigner`]s, in order to
    /// sign a JWS using them.
    ///
    /// # Errors
    ///
    /// Fails if one of the JWKs could not be converted to a signer.
    pub fn into_signers(self) -> Result<Vec<JwkSigner>, FromJwkError> {
        let signers: Vec<JwkSigner> = self
            .keys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signers)
    }

    /// Tries to convert all keys in this set to [`JwkSigner`]s, in order to
    /// sign a JWS using them. But instead of taking `self`, it will clone
    /// all keys.
    ///
    /// # Errors
    ///
    /// Fails if one of the JWKs could not be converted to a signer.
    pub fn signers(&self) -> Result<Vec<JwkSigner>, FromJwkError>
    where
        A: Clone,
        P: Clone,
    {
        let signers: Vec<JwkSigner> = self
            .keys
            .iter()
            .cloned()
            .map(|x| x.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signers)
    }

    /// Tries to convert all keys in this set to [`JwkVerifier`]s, in order to
    /// verify a JWS using them.
    ///
    /// # Errors
    ///
    /// Fails if one of the JWKs could not be converted to a verifier.
    pub fn into_verifiers(self) -> Result<Vec<JwkVerifier>, FromJwkError> {
        let verifiers: Vec<JwkVerifier> = self
            .keys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(verifiers)
    }

    /// Tries to convert all keys in this set to [`JwkVerifier`]s, in order to
    /// verify a JWS using them. But instead of taking `self`, it will clone
    /// all keys.
    ///
    /// # Errors
    ///
    /// Fails if one of the JWKs could not be converted to a verifier.
    pub fn verifiers(&self) -> Result<Vec<JwkVerifier>, FromJwkError>
    where
        A: Clone,
        P: Clone,
    {
        let verifiers: Vec<JwkVerifier> = self
            .keys
            .iter()
            .cloned()
            .map(|x| x.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(verifiers)
    }

    /// Tries to find the JWK for the given key id, and then converts that JWK
    /// into a [`JwkSigner`].
    pub fn signer_for_key_id(&self, key_id: &str) -> Option<Result<JwkSigner, FromJwkError>>
    where
        A: Clone,
        P: Clone,
    {
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id().is_some_and(|id| id == key_id))?;

        Some(JwkSigner::try_from(Checked::clone(key)))
    }

    /// Tries to find the JWK for the given key id, and then converts that JWK
    /// into a [`JwkVerifier`].
    pub fn verifier_for_key_id(&self, key_id: &str) -> Option<Result<JwkVerifier, FromJwkError>>
    where
        A: Clone,
        P: Clone,
    {
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id().is_some_and(|id| id == key_id))?;

        Some(JwkVerifier::try_from(Checked::clone(key)))
    }
}
