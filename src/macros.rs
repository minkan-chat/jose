macro_rules! ec_signer {
    ($(#[$meta:meta])* $name:ident, $priv:ty, $crv:ty, $alg:stmt, $($pattern:pat_param)+) => {
        $(#[$meta])*
        #[derive(Debug)]
        #[allow(unused_qualifications)]
        pub struct $name(ecdsa::SigningKey<$crv>);
        #[allow(unused_qualifications)]
        impl crate::jws::Signer<ecdsa::Signature<$crv>> for $name {
            fn sign(&mut self, msg: &[u8]) -> Result<ecdsa::Signature<$crv>, signature::Error> {
                signature::Signer::try_sign(&self.0, msg)
            }

            fn algorithm(&self) -> crate::jwa::JsonWebSigningAlgorithm {
                $alg
            }
        }

        #[allow(unused_qualifications)]
        impl crate::jws::FromKey<$priv, ecdsa::Signature<$crv>> for $name {
            type Error = crate::jws::InvalidSigningAlgorithmError;
            fn from_key(key: $priv, alg: crate::jwa::JsonWebSigningAlgorithm) -> Result<$name, crate::jws::InvalidSigningAlgorithmError> {
                let key: ecdsa::SigningKey<$crv> = key.0.into();
                match alg {
                    $($pattern)+ => Ok(Self(key)),
                    _ => Err(crate::jws::InvalidSigningAlgorithmError),
                }
            }
        }
    };
}

macro_rules! impl_serde_ec {
    ($public:ty, $private:ty, $curve:literal, $key_type:literal, $inner:ty) => {
        #[allow(unused_qualifications)]
        impl<'de> serde::Deserialize<'de> for $public {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let key = crate::jwk::ec::EcPublicKey::deserialize(deserializer)?;

                if &*key.crv != $curve {
                    return Err(<D::Error as serde::de::Error>::custom(alloc::format!(
                        "Invalid curve type `{}`. Expected: `{}`",
                        &*key.crv,
                        $curve,
                    )));
                }

                if &*key.kty != $key_type {
                    return Err(<D::Error as serde::de::Error>::custom(alloc::format!(
                        "Invalid key type `{}`. Expected: `{}`",
                        &*key.kty,
                        $key_type,
                    )));
                }

                Ok(Self(
                    key.to_public_key()
                        .map_err(<D::Error as serde::de::Error>::custom)?,
                ))
            }
        }

        #[allow(unused_qualifications)]
        impl<'de> serde::Deserialize<'de> for $private {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let key = crate::jwk::ec::EcPrivateKey::deserialize(deserializer)?;
                if &*key.public_part.crv != $curve {
                    return Err(<D::Error as serde::de::Error>::custom(alloc::format!(
                        "Invalid curve type `{}`. Expected: `{}`",
                        &*key.public_part.crv,
                        $curve,
                    )));
                }
                if &*key.public_part.kty != $key_type {
                    return Err(<D::Error as serde::de::Error>::custom(alloc::format!(
                        "Invalid key type `{}`. Expected: `{}`",
                        &*key.public_part.kty,
                        $key_type,
                    )));
                }

                Ok(Self(
                    key.to_secret_key()
                        .map_err(<D::Error as serde::de::Error>::custom)?,
                ))
            }
        }

        #[allow(unused_qualifications)]
        impl serde::Serialize for $public {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let key = &self.0;

                #[derive(serde::Serialize)]
                struct Repr<'a> {
                    crv: &'a str,
                    kty: &'a str,
                    x: crate::base64_url::Base64UrlEncodedField<$inner>,
                    y: crate::base64_url::Base64UrlEncodedField<$inner>,
                }

                use elliptic_curve::sec1::ToEncodedPoint;
                let point = key.to_encoded_point(false);
                let x = point.x().map(AsRef::as_ref).unwrap_or(&[0u8][..]);
                let y = point.y().map(AsRef::as_ref).unwrap_or(&[0u8][..]);

                let repr = Repr {
                    crv: $curve,
                    kty: $key_type,
                    x: crate::base64_url::Base64UrlEncodedField(
                        *generic_array::GenericArray::from_slice(x),
                    ),
                    y: crate::base64_url::Base64UrlEncodedField(
                        *generic_array::GenericArray::from_slice(y),
                    ),
                };

                repr.serialize(serializer)
            }
        }

        #[allow(unused_qualifications)]
        impl serde::Serialize for $private {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let key = &self.0;

                #[derive(serde::Serialize)]
                struct Repr<'a> {
                    crv: &'a str,
                    kty: &'a str,
                    x: crate::base64_url::Base64UrlEncodedField<$inner>,
                    y: crate::base64_url::Base64UrlEncodedField<$inner>,
                    d: crate::base64_url::Base64UrlEncodedField<$inner>,
                }

                use elliptic_curve::sec1::ToEncodedPoint;
                let point = key.public_key().to_encoded_point(false);
                let x = point.x().map(AsRef::as_ref).unwrap_or(&[0u8][..]);
                let y = point.y().map(AsRef::as_ref).unwrap_or(&[0u8][..]);

                let repr = Repr {
                    crv: $curve,
                    kty: $key_type,
                    x: crate::base64_url::Base64UrlEncodedField(
                        *generic_array::GenericArray::from_slice(x),
                    ),
                    y: crate::base64_url::Base64UrlEncodedField(
                        *generic_array::GenericArray::from_slice(y),
                    ),
                    d: crate::base64_url::Base64UrlEncodedField(key.to_be_bytes()),
                };

                repr.serialize(serializer)
            }
        }
    };
}

macro_rules! impl_serde_jwa {
    ($T:ty, [
        $($name:literal => $val:expr; $valp:pat,)*
        err: $err:ident => $get_err:expr, $(,)?
    ]) => {
        #[allow(unused_qualifications)]
        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let name = <&str as serde::Deserialize>::deserialize(deserializer)?;

                Ok(match name {
                    $($name => $val,)*
                    $err => return Err(<D::Error as serde::de::Error>::custom($get_err)),
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
                    deserializer.deserialize_any(TaggedContentVisitor::new($tag, $expecting))?;

                match tagged.tag {
                    $(Tag::$i => Deserialize::deserialize(tagged.content).map(<$T>::$i),)*
                    //Tag::P256 => Deserialize::deserialize(tagged.content).map(Self::P256),
                    //Tag::P384 => Deserialize::deserialize(tagged.content).map(Self::P384),
                    //Tag::Secp256k1 => Deserialize::deserialize(tagged.content).map(Self::Secp256k1),
                }
                .map_err(|x| x.into_error())
            }
        }
    };
}

macro_rules! hs_signer {
    ($(#[$meta:meta])* $name:ident, $hash:ty, $alg:expr, $expected:pat_param) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name {
            key: Hmac<$hash>,
        }

        impl Signer<Output<Hmac<$hash>>> for $name {
            fn sign(&mut self, msg: &[u8]) -> Result<Output<Hmac<$hash>>, signature::Error> {
                self.key.update(msg);
                Ok(self.key.finalize_reset().into_bytes())
            }

            fn algorithm(&self) -> JsonWebSigningAlgorithm {
                JsonWebSigningAlgorithm::Hmac($alg)
            }
        }

        impl FromKey<&'_ OctetSequence, Output<Hmac<$hash>>> for $name {
            type Error = FromOctetSequenceError;

            fn from_key(
                key: &'_ OctetSequence,
                alg: JsonWebSigningAlgorithm,
            ) -> Result<$name, FromOctetSequenceError> {
                match alg {
                    JsonWebSigningAlgorithm::Hmac($expected) => {
                        let key: Hmac<$hash> = Hmac::new_from_slice(&key.0)?;
                        Ok(Self { key })
                    }
                    _ => Err(InvalidSigningAlgorithmError.into()),
                }
            }
        }

        impl TryFrom<&'_ OctetSequence> for $name {
            type Error = InvalidLength;

            fn try_from(key: &'_ OctetSequence) -> Result<Self, Self::Error> {
                let key: Hmac<$hash> = Hmac::new_from_slice(&key.0)?;
                Ok(Self { key })
            }
        }
    };
}