use alloc::vec::Vec;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    md::Md,
    md_ctx::MdCtx,
    pkey::{PKey, Private, Public},
    sign::Verifier,
};
use secrecy::{ExposeSecret, SecretSlice};

use crate::{
    crypto::{
        backend::interface::ec,
        ec::{coordinate_size, scalar_size},
        Result,
    },
    jwa::{self, EcDSA},
};

fn ec_group(alg: jwa::EcDSA) -> Result<EcGroup> {
    let group = match alg {
        EcDSA::Es256 => EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?,
        EcDSA::Es384 => EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1)?,
        EcDSA::Es512 => EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1)?,
        EcDSA::Es256K => EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)?,
    };

    Ok(group)
}

fn digest(alg: jwa::EcDSA) -> MessageDigest {
    match alg {
        EcDSA::Es256 => MessageDigest::sha256(),
        EcDSA::Es384 => MessageDigest::sha384(),
        EcDSA::Es512 => MessageDigest::sha512(),
        EcDSA::Es256K => MessageDigest::sha256(),
    }
}

/// A low level private EC key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    alg: jwa::EcDSA,

    key: PKey<Private>,
    public_key: PKey<Public>,

    d: SecretSlice<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl ec::PrivateKey for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Vec<u8>;

    fn generate(alg: jwa::EcDSA) -> Result<Self> {
        let group = ec_group(alg)?;

        let ec_key = EcKey::generate(&group)?;
        ec_key.check_key()?;

        let public_point = ec_key.public_key();
        let public_key = EcKey::from_public_key(&group, public_point)?;

        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        public_point.affine_coordinates(&group, &mut x, &mut y, &mut ctx)?;

        let coordinate_size = coordinate_size(alg) as i32;
        Ok(Self {
            alg,
            public_key: PKey::from_ec_key(public_key)?,
            d: SecretSlice::from(
                ec_key
                    .private_key()
                    .to_vec_padded(scalar_size(alg) as i32)?,
            ),
            key: PKey::from_ec_key(ec_key)?,
            x: x.to_vec_padded(coordinate_size)?,
            y: y.to_vec_padded(coordinate_size)?,
        })
    }

    fn new(alg: EcDSA, x: Vec<u8>, y: Vec<u8>, d: SecretSlice<u8>) -> Result<Self> {
        let group = ec_group(alg)?;

        let d = BigNum::from_slice(d.expose_secret())?;
        let x = BigNum::from_slice(&x)?;
        let y = BigNum::from_slice(&y)?;

        let public_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
        public_key.check_key()?;

        let key = EcKey::from_private_components(&group, &d, public_key.public_key())?;
        key.check_key()?;

        let coordinate_size = coordinate_size(alg) as i32;
        Ok(Self {
            alg,
            key: PKey::from_ec_key(key.clone())?,
            d: SecretSlice::from(key.private_key().to_vec_padded(scalar_size(alg) as i32)?),
            public_key: PKey::from_ec_key(public_key)?,
            x: x.to_vec_padded(coordinate_size)?,
            y: y.to_vec_padded(coordinate_size)?,
        })
    }

    fn private_material(&self) -> SecretSlice<u8> {
        self.d.clone()
    }

    #[inline]
    fn public_point(&self) -> (Vec<u8>, Vec<u8>) {
        (self.x.clone(), self.y.clone())
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey {
            digest: digest(self.alg),
            key: self.public_key.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }

    fn sign(&mut self, data: &[u8], deterministic: bool) -> Result<Self::Signature> {
        let mut md_ctx = MdCtx::new()?;

        let md = match self.alg {
            EcDSA::Es256 => Md::sha256(),
            EcDSA::Es384 => Md::sha384(),
            EcDSA::Es512 => Md::sha512(),
            EcDSA::Es256K => Md::sha256(),
        };

        #[allow(unused_variables)]
        let pkey_ctx = md_ctx.digest_sign_init(Some(md), &self.key)?;

        if deterministic {
            #[cfg(all(not(feature = "crypto-aws-lc"), openssl320))]
            pkey_ctx.set_nonce_type(openssl::pkey_ctx::NonceType::DETERMINISTIC_K)?;

            #[cfg(any(feature = "crypto-aws-lc", not(openssl320)))]
            return Err(super::BackendError::Unsupported(
                "deterministic signing for EcDSA".to_string(),
            )
            .into());
        }

        md_ctx.digest_update(data)?;

        let mut der_sig = vec![];
        md_ctx.digest_sign_final_to_vec(&mut der_sig)?;

        // the returned signature is in DER format, we need to convert it according
        // to Section 3.4 of RFC 7518
        let signature = EcdsaSig::from_der(&der_sig)?;
        let r = signature.r().to_vec_padded(32)?;
        let s = signature.s().to_vec_padded(32)?;

        let mut sig = Vec::with_capacity(r.len() + s.len());
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&s);

        Ok(sig)
    }
}

/// A low level public EC key.
#[derive(Clone)]
pub(crate) struct PublicKey {
    digest: MessageDigest,
    key: PKey<Public>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl ec::PublicKey for PublicKey {
    fn new(alg: EcDSA, raw_x: Vec<u8>, raw_y: Vec<u8>) -> Result<Self> {
        let group = ec_group(alg)?;

        let x = BigNum::from_slice(&raw_x)?;
        let y = BigNum::from_slice(&raw_y)?;

        let public_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
        public_key.check_key()?;
        let key = PKey::from_ec_key(public_key)?;

        let coordinate_size = coordinate_size(alg) as i32;
        Ok(Self {
            digest: digest(alg),
            key,
            x: x.to_vec_padded(coordinate_size)?,
            y: y.to_vec_padded(coordinate_size)?,
        })
    }

    fn to_point(&self) -> (Vec<u8>, Vec<u8>) {
        (self.x.clone(), self.y.clone())
    }

    fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<bool> {
        // the signature is r and s concatenated, but we need it in DER format for
        // OpenSSL

        let (r, s) = signature.split_at(signature.len() / 2);
        let r = BigNum::from_slice(r)?;
        let s = BigNum::from_slice(s)?;

        let signature = EcdsaSig::from_private_components(r, s)?.to_der()?;

        let mut verifier = Verifier::new(self.digest, &self.key)?;
        verifier.update(msg)?;
        let valid = verifier.verify(&signature)?;

        Ok(valid)
    }
}
