//! Implementation of JSON Web Encryption (JWE) as defined in [RFC 7516]
//!
//! [RFC 7516]: <https://www.rfc-editor.org/rfc/rfc7516.html>

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{convert::Infallible, fmt::Debug, str::FromStr};

use decrypt::{Decrypted, Decryptor};
use encrypt::{Encrypted, EncryptedKey, Encryptor};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};

use crate::{
    base64_url::Base64UrlBytes,
    format::{sealed::SealedFormatJwe, Compact, CompactJwe, DecodeFormat, JsonGeneralJwe},
    header,
    jws::{FromRawPayload, ParseJsonError},
    sealed::Sealed,
    JoseHeader,
};

pub mod decrypt;
pub mod encrypt;

impl SealedFormatJwe for CompactJwe {
    type JweHeader = JoseHeader<Self, header::Jwe>;

    fn serialize_header(header: Self::JweHeader) -> String {
        let (protected, _) = header.into_values().unwrap();
        serde_json::to_string(&protected.unwrap()).unwrap()
    }
}

/// TODO
#[derive(Debug)]
pub struct JsonWebEncryption<F, T = ()>
where
    F: SealedFormatJwe,
{
    header: F::JweHeader,
    /// The decrypted payload
    payload: T,
}

impl<F, P> JsonWebEncryption<F, P>
where
    F: SealedFormatJwe<JweHeader = JoseHeader<F, header::Jwe>>,
    P: Serialize,
{
    pub fn encrypt<T: AsRef<[u8]>>(self, encryptor: &mut dyn Encryptor<T>) -> Encrypted<F> {
        let header = self.header;
        let payload = serde_json::to_vec(&self.payload).unwrap();
        // iv, etc. from format
        let (ciphertext, encrypted_key) = encryptor.encrypt(&payload).unwrap();
        Encrypted {
            ciphertext: Base64UrlBytes(ciphertext.as_ref().to_vec()),
            encrypted_key,
            header,
            iv: None,
            tag: None,
        }
    }
}

impl<F: SealedFormatJwe> Sealed for Encrypted<F> {}

impl DecodeFormat<CompactJwe> for Encrypted<CompactJwe> {
    type Decoded<T> = Encrypted<CompactJwe>;
    type Error = Infallible;

    fn decode(input: CompactJwe) -> Result<Self::Decoded<Self>, Self::Error> {
        let header = input.part(0).unwrap();
        let encrypted_key = input.part(1).unwrap();
        let initalization_vector = input.part(2).unwrap();
        let ciphertext = input.part(3).unwrap();
        let authentication_tag = input.part(4).unwrap();

        let header: Map<String, Value> = serde_json::from_slice(&header.decode()).unwrap();
        let header = JoseHeader::from_values(Some(header), None).unwrap();

        let encrypted_key = EncryptedKey {
            enc: header
                .content_encryption_algorithm()
                .protected()
                .unwrap()
                .to_owned(),
            material: Base64UrlBytes(encrypted_key.decode()),
        };
        Ok(Encrypted {
            header,
            encrypted_key,
            iv: Some(Base64UrlBytes(initalization_vector.decode())),
            ciphertext: Base64UrlBytes(ciphertext.decode()),
            tag: Some(Base64UrlBytes(authentication_tag.decode())),
        })
    }
}

impl<F> Encrypted<F>
where
    Encrypted<F>: DecodeFormat<F, Decoded<Encrypted<F>> = Self>,
    F: SealedFormatJwe<JweHeader = JoseHeader<F, header::Jwe>>,
    // FIXME: remove bond
    <Encrypted<F> as DecodeFormat<F>>::Error: Debug,
{
    /// Tries to decrypt the payload contained in `self`
    ///
    /// # Errors
    pub fn decrypt<T>(
        self,
        decryptor: &mut dyn Decryptor,
    ) -> Result<Decrypted<JsonWebEncryption<F, T>>, Infallible>
    where
        T: DeserializeOwned,
    {
        let (decrypted, encryption_key) = decryptor
            .decrypt(
                self.encrypted_key,
                self.header.algorithm().into_inner(),
                &self.ciphertext.0,
            )
            .unwrap();
        let inner = JsonWebEncryption::<F, T> {
            header: self.header,
            payload: serde_json::from_slice(&decrypted).unwrap(),
        };
        Ok(Decrypted {
            encryption_key,
            inner,
        })
    }

    /// Tries to create `self` from encoded string
    ///
    /// # Errors
    pub fn decode(input: F) -> Result<Self, Infallible>
where {
        Ok(<Self as DecodeFormat<F>>::decode(input).unwrap())
    }

    pub fn encode(self) -> F {
        todo!()
    }
}

mod tests {
    use alloc::{string::String, vec::Vec};

    use super::{
        decrypt::Decryptor,
        encrypt::{Encrypted, Encryptor},
        JsonWebEncryption,
    };
    use crate::{format::CompactJwe, jwa::JsonWebEncryptionAlgorithm};

    fn test() {
        let raw = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";

        let encoded: CompactJwe = raw.parse().unwrap();
        let encrypted = Encrypted::decode(encoded).unwrap();
        let decrypted = encrypted.decrypt::<String>(&mut Dummy).unwrap();
        let jwe = decrypted.inner;
        let encrypted = jwe.encrypt(&mut Dummy);
        let encoded = encrypted.encode();
    }

    struct Dummy;

    impl Decryptor for Dummy {
        fn decrypt(
            &mut self,
            encrypted_key: super::encrypt::EncryptedKey,
            alg: &crate::jwa::JsonWebEncryptionAlgorithm,
            payload: &[u8],
        ) -> Result<(alloc::vec::Vec<u8>, super::encrypt::EncryptionKey), crate::crypto::Error>
        {
            todo!()
        }
    }

    impl Encryptor<Vec<u8>> for Dummy {
        fn encrypt(
            &mut self,
            payload: &[u8],
        ) -> Result<(alloc::vec::Vec<u8>, super::encrypt::EncryptedKey), crate::crypto::Error>
        {
            todo!()
        }

        fn algorithm(&self) -> JsonWebEncryptionAlgorithm {
            JsonWebEncryptionAlgorithm::Rsa1_5
        }

        fn content_encryption_algorithm(&self) -> crate::jwa::JsonWebContentEncryptionAlgorithm {
            crate::jwa::JsonWebContentEncryptionAlgorithm::AesCbcHs(
                crate::jwa::AesCbcHs::Aes128CbcHs256,
            )
        }
    }
}
