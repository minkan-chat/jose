macro_rules! impl_ec {
    ($signer:ident, $priv:ident, $crv:ty, $alg:expr, $($pattern:pat_param)+,
    $ec_priv_name:ident,
    $verifier:ident,
    $public:path) => {
        impl $priv {
            /// Generate a new private key using the provided rng
            pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Self {
                Self(elliptic_curve::SecretKey::random(rng))
            }

            /// Get the public key corresponding to this private key.
            pub fn to_public_key(&self) -> $public {
                $public(self.0.public_key())
            }
        }

        impl From<$priv> for crate::jwk::JsonWebKeyType {
            fn from(x: $priv) -> Self {
                crate::jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
                    crate::jwk::AsymmetricJsonWebKey::Private(
                        crate::jwk::Private::Ec(crate::jwk::EcPrivate::$ec_priv_name(x))
                    ),
                ))
            }
        }

        impl From<$public> for crate::jwk::JsonWebKeyType {
            fn from(x: $public) -> Self {
                crate::jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
                    crate::jwk::AsymmetricJsonWebKey::Public(
                        crate::jwk::Public::Ec(crate::jwk::EcPublic::$ec_priv_name(x))
                    ),
                ))
            }
        }

        impl crate::sealed::Sealed for $public {}
        impl crate::jwk::IntoJsonWebKey for $public {
            /// Algorithm is `()` because there's only
            /// one algorithm for this key type.
            type Algorithm = ();
            type Error = core::convert::Infallible;

            fn into_jwk(
                self,
                alg: impl Into<Option<Self::Algorithm>>,
            ) -> Result<crate::JsonWebKey, Self::Error> {
                let key = crate::jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
                    crate::jwk::AsymmetricJsonWebKey::Public(crate::jwk::Public::Ec(
                        super::EcPublic::$ec_priv_name(self),
                    )),
                ));

                let mut jwk = crate::JsonWebKey::new(key);
                jwk.algorithm = alg.into().map(|_| crate::jwa::JsonWebKeyAlgorithm::Signing($alg));
                Ok(jwk)
            }
        }

        impl crate::sealed::Sealed for $priv {}
        impl crate::jwk::IntoJsonWebKey for $priv {
            /// Algorithm is `()` because there's only
            /// one algorithm for this key type.
            type Algorithm = ();
            type Error = core::convert::Infallible;

            fn into_jwk(
                self,
                alg: impl Into<Option<Self::Algorithm>>,
            ) -> Result<crate::JsonWebKey, Self::Error> {
                let key = crate::jwk::JsonWebKeyType::Asymmetric(alloc::boxed::Box::new(
                    crate::jwk::AsymmetricJsonWebKey::Private(crate::jwk::Private::Ec(
                        super::EcPrivate::$ec_priv_name(self),
                    )),
                ));

                let mut jwk = crate::JsonWebKey::new(key);
                jwk.algorithm = alg.into().map(|_| crate::jwa::JsonWebKeyAlgorithm::Signing($alg));
                Ok(jwk)
            }
        }

        #[doc = concat!("A [`Signer`](crate::jws::Signer) using a [`", stringify!($priv), "`]")]
        #[derive(Debug)]
        #[allow(unused_qualifications)]
        pub struct $signer(ecdsa::SigningKey<$crv>);

        #[allow(unused_qualifications)]
        impl crate::jws::Signer<ecdsa::SignatureBytes<$crv>> for $signer {
            type Digest = <$crv as ecdsa::hazmat::DigestPrimitive>::Digest;

            fn new_digest(&self) -> Self::Digest {
                Self::Digest::default()
            }

            fn sign_digest(&mut self, digest: Self::Digest) -> Result<ecdsa::SignatureBytes<$crv>, signature::Error> {
                signature::DigestSigner::try_sign_digest(&self.0, digest).map(|(sig, _)| sig.to_bytes())
            }

            fn algorithm(&self) -> crate::jwa::JsonWebSigningAlgorithm {
                $alg
            }
        }

        #[allow(unused_qualifications)]
        impl crate::jwk::FromKey<$priv> for $signer {
            type Error = crate::jws::InvalidSigningAlgorithmError;
            fn from_key(key: $priv, alg: crate::jwa::JsonWebAlgorithm) -> Result<$signer, crate::jws::InvalidSigningAlgorithmError> {
                match alg {
                    crate::jwa::JsonWebAlgorithm::Signing($($pattern)+) => {
                        let key: ecdsa::SigningKey<$crv> = key.0.into();
                        Ok(Self(key))
                    },
                    _ => Err(crate::jws::InvalidSigningAlgorithmError),
                }
            }
        }

        #[doc = concat!("A [`Verifier`](crate::jws::Verifier) using a [`", stringify!($public), "`]")]
        #[derive(Debug)]
        #[allow(unused_qualifications)]
        pub struct $verifier(ecdsa::VerifyingKey<$crv>);

        #[allow(unused_qualifications)]
        impl crate::jws::Verifier for $verifier {
            fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), signature::Error> {
                let signature: ecdsa::Signature<$crv> = signature.try_into()?;
                signature::Verifier::verify(&self.0, msg, &signature)
            }
        }

        impl crate::jwk::FromKey<$public> for $verifier {
            type Error = crate::jws::InvalidSigningAlgorithmError;

            fn from_key(key: $public, alg: crate::jwa::JsonWebAlgorithm) -> Result<$verifier, Self::Error> {
                let key: ecdsa::VerifyingKey<$crv> = key.0.into();
                match alg {
                    crate::jwa::JsonWebAlgorithm::Signing($($pattern)+) => Ok(Self(key)),
                    _ => Err(crate::jws::InvalidSigningAlgorithmError)
                }
            }
        }

        /// Create a [`Verifier`](crate::jws::Verifier) from the private key by turning it into the public key and dropping the private parts afterwards
        impl crate::jwk::FromKey<$priv> for $verifier {
            type Error = crate::jws::InvalidSigningAlgorithmError;
            fn from_key(key: $priv, alg: crate::jwa::JsonWebAlgorithm) -> Result<$verifier, Self::Error> {
                let key: ecdsa::SigningKey<$crv> = ecdsa::SigningKey::<$crv>::from(key.0);

                match alg {
                    crate::jwa::JsonWebAlgorithm::Signing($($pattern)+) => Ok(Self(ecdsa::VerifyingKey::from(&key))),
                    _ => Err(crate::jws::InvalidSigningAlgorithmError)
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

                Ok(Self(key.to_public_key().ok_or_else(|| {
                    <D::Error as serde::de::Error>::custom("Invalid public key")
                })?))
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
                    d: crate::base64_url::Base64UrlEncodedField(key.to_bytes()),
                };

                repr.serialize(serializer)
            }
        }
    };
}

macro_rules! impl_serde_jwa {
    ($T:ty, [
        $($name:literal => $val:expr; $valp:pat,)*

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
                    _ => Self::Other(name.into_owned()),
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
                    deserializer.deserialize_any(TaggedContentVisitor::new($tag, $expecting))?;

                match tagged.tag {
                    $(Tag::$i => Deserialize::deserialize(tagged.content).map(<$T>::$i),)*
                }
                .map_err(|x| x.into_error())
            }
        }
    };
}
