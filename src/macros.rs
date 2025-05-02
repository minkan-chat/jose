macro_rules! impl_serde_jwa {
    ($T:ty, [
        $($name:literal => $val:expr; $valp:pat,)*
    ]) => {

        impl core::fmt::Display for $T {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match &self {
                    $($valp => write!(f, "{}", $name),)*
                    Self::Other(other) => write!(f, "{}", other),
                }
            }
        }
        #[allow(unused_qualifications)]
        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let name = <alloc::borrow::Cow<'_, str> as serde::Deserialize>::deserialize(deserializer)?;

                Ok(Self::from_str_without_other(&name).unwrap_or_else(|| {
                    Self::Other(name.into_owned())
                }))
            }
        }

        #[allow(unused_qualifications)]
        impl serde::Serialize for $T {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let name = match self {
                    $($valp => $name,)*
                    Self::Other(custom) => custom,
                };
                <&str as serde::Serialize>::serialize(&name, serializer)
            }
        }

        impl $T {
            /// Tries to parse the given name into a variant, and returns `None`
            /// if no variant matched.
            pub(crate) fn from_str_without_other(name: &str) -> Option<Self> {
                match name {
                    $($name => Some($val),)*
                    _ => None,
                }
            }
        }
    };
}

macro_rules! impl_internally_tagged_deserialize {
    ($T:ty, $tag:literal, $expecting:literal, [$($name:literal => $i:ident),* $(,)?]) => {
        #[allow(unused_qualifications)]
        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(Clone, Copy, Deserialize)]
                enum Tag {
                    $(#[serde(rename = $name)]
                    $i,)*
                }

                let tagged =
                    deserializer.deserialize_any(crate::tagged_visitor::TaggedContentVisitor::new($tag, $expecting))?;

                match tagged.tag {
                    $(Tag::$i => Deserialize::deserialize(tagged.content).map(<$T>::$i),)*
                }
                .map_err(|x| x.into_error())
            }
        }
    };
}

macro_rules! impl_thumbprint_hash_trait {
    ($symmetric:ty) => {
        #[allow(rustdoc::redundant_explicit_links)]
        /// The [`Hash`](core::hash::Hash) implementation uses
        /// [`Thumbprint::thumbprint_prehashed`](crate::jwk::Thumbprint::thumbprint_prehashed)
        impl core::hash::Hash for $symmetric {
            fn hash<H>(&self, state: &mut H)
            where
                H: core::hash::Hasher,
            {
                alloc::format!(
                    "symmetric:{}",
                    <$symmetric as crate::jwk::Thumbprint>::thumbprint_prehashed(&self)
                )
                .hash(state)
            }
        }
    };
    ($public:ty, $private:ty) => {
        #[allow(rustdoc::redundant_explicit_links)]
        /// The [`Hash`](core::hash::Hash) implementation uses
        /// [`Thumbprint::thumbprint_prehashed`](crate::jwk::Thumbprint::thumbprint_prehashed)
        impl core::hash::Hash for $public {
            fn hash<H>(&self, state: &mut H)
            where
                H: core::hash::Hasher,
            {
                alloc::format!(
                    "public:{}",
                    <$public as crate::jwk::Thumbprint>::thumbprint_prehashed(&self)
                )
                .hash(state)
            }
        }
        #[allow(rustdoc::redundant_explicit_links)]
        /// The [`Hash`](core::hash::Hash) implementation uses
        /// [`Thumbprint::thumbprint_prehashed`](crate::jwk::Thumbprint::thumbprint_prehashed)
        impl core::hash::Hash for $private {
            fn hash<H>(&self, state: &mut H)
            where
                H: core::hash::Hasher,
            {
                alloc::format!(
                    "private:{}",
                    <$private as crate::jwk::Thumbprint>::thumbprint_prehashed(&self)
                )
                .hash(state)
            }
        }
    };
}
