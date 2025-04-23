macro_rules! impl_serde_jwa {
    ($T:ty, [
        $($name:literal => $val:expr; $valp:pat,)*

        $(contrary: <$contrary:ty>::$contrary_variant:ident,)?

        expected: $expected:literal,
        got: $got:literal,
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

                Ok(match name.as_ref() {
                    $($name => $val,)*
                    _ => {
                        $(
                            use $contrary as _Contrary;
                            let de: serde::de::value::CowStrDeserializer<'_, D::Error> = serde::de::value::CowStrDeserializer::new(name);
                            let variant: $contrary = <$contrary>::deserialize(de)?;
                            if let _Contrary::$contrary_variant(name) = variant {
                                return Ok(Self::Other(name));
                            } else {
                                let fmt = alloc::format!("{} `{}`", $got, variant);
                                let unexpected = serde::de::Unexpected::Str(&fmt);
                                return Err(<D::Error as serde::de::Error>::invalid_value(unexpected, &$expected));
                            }
                        )*
                        // this will be reachable if contrary is not present
                        #[allow(unreachable_code)]
                        Self::Other(name.into_owned())
                    },
                })
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
