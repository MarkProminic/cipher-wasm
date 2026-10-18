use crate::error::{Error, Result};
use crate::pem;
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params as ArgonParams, Version as ArgonVersion};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_EC_PUBLIC_KEY, RSA_ENCRYPTION,
    SECP_256_R_1, SECP_384_R_1, SHA_1_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc8410::ID_ED_25519;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{Any, AnyRef};
use der::Decode;
use digest::Digest;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use pkcs5::pbes2;
use pkcs8::{EncodePrivateKey, PrivateKeyInfo};
use rand_core::{OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::BigUint;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::{SignatureEncoding, Signer, Verifier};
use spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoRef};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey as SshRsaPublicKey};
use ssh_key::{LineEnding, Mpint};
use wasm_bindgen::JsValue;

pub const PBKDF2_ITERATIONS: u32 = 2048;

#[derive(Serialize, Clone, Debug)]
pub struct KeyFacts {
    pub algorithm: String,
    pub bits: u32,
    pub curve: Option<String>,
    pub public_key_sha256: String,
    pub has_private: bool,
}

pub enum PrivateKey {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Ed25519(ed25519_dalek::SigningKey),
}

pub enum PublicKey {
    Rsa(rsa::RsaPublicKey),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

fn unsupported_algorithm() -> Error {
    Error::new("The key algorithm is not supported; only RSA, P-256, P-384 and Ed25519 are.")
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn spki_sha256_hex(spki_der: &[u8]) -> String {
    pem::hex(&Sha256::digest(spki_der))
}

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let info = PrivateKeyInfo::from_der(der)?;
        match info.algorithm.oid {
            RSA_ENCRYPTION => Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::try_from(info)?)),
            ID_EC_PUBLIC_KEY => match info.algorithm.parameters_oid()? {
                SECP_256_R_1 => Ok(PrivateKey::P256(p256::SecretKey::try_from(info)?)),
                SECP_384_R_1 => Ok(PrivateKey::P384(p384::SecretKey::try_from(info)?)),
                _ => Err(unsupported_algorithm()),
            },
            ID_ED_25519 => Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::try_from(
                info,
            )?)),
            _ => Err(unsupported_algorithm()),
        }
    }

    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::from_pkcs1_der(der)?))
    }

    pub fn from_sec1_der(der: &[u8]) -> Result<Self> {
        if let Ok(k) = p256::SecretKey::from_sec1_der(der) {
            return Ok(PrivateKey::P256(k));
        }
        if let Ok(k) = p384::SecretKey::from_sec1_der(der) {
            return Ok(PrivateKey::P384(k));
        }
        Err(Error::new("The EC private key is not on P-256 or P-384."))
    }

    pub fn from_any_der(der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(der)
            .or_else(|_| Self::from_pkcs1_der(der))
            .or_else(|_| Self::from_sec1_der(der))
    }

    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let doc = match self {
            PrivateKey::Rsa(k) => k.to_pkcs8_der()?,
            PrivateKey::P256(k) => k.to_pkcs8_der()?,
            PrivateKey::P384(k) => k.to_pkcs8_der()?,
            PrivateKey::Ed25519(k) => k.to_pkcs8_der()?,
        };
        Ok(doc.as_bytes().to_vec())
    }

    pub fn to_pkcs1_der(&self) -> Result<(&'static str, Vec<u8>)> {
        match self {
            PrivateKey::Rsa(k) => Ok(("RSA PRIVATE KEY", k.to_pkcs1_der()?.as_bytes().to_vec())),
            PrivateKey::P256(k) => Ok(("EC PRIVATE KEY", k.to_sec1_der()?.to_vec())),
            PrivateKey::P384(k) => Ok(("EC PRIVATE KEY", k.to_sec1_der()?.to_vec())),
            PrivateKey::Ed25519(_) => Err(Error::new("Ed25519 keys have no PKCS#1 or SEC1 form.")),
        }
    }

    pub fn to_encrypted_pkcs8_der(&self, password: &str) -> Result<Vec<u8>> {
        let der = self.to_pkcs8_der()?;
        let info = PrivateKeyInfo::from_der(&der)?;
        let salt = random_bytes(16);
        let iv_vec = random_bytes(16);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_vec);
        let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, &salt, &iv)?;
        let doc = info.encrypt_with_params(params, password.as_bytes())?;
        Ok(doc.as_bytes().to_vec())
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.to_public_key()),
            PrivateKey::P256(k) => PublicKey::P256(k.public_key()),
            PrivateKey::P384(k) => PublicKey::P384(k.public_key()),
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
        }
    }

    pub fn generate(alg: &str) -> Result<Self> {
        match alg {
            "rsa2048" => Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::new(&mut OsRng, 2048)?)),
            "rsa3072" => Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::new(&mut OsRng, 3072)?)),
            "rsa4096" => Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::new(&mut OsRng, 4096)?)),
            "p256" => Ok(PrivateKey::P256(p256::SecretKey::random(&mut OsRng))),
            "p384" => Ok(PrivateKey::P384(p384::SecretKey::random(&mut OsRng))),
            "ed25519" => Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng))),
            _ => Err(Error::new(
                "The key algorithm must be one of rsa2048, rsa3072, rsa4096, p256, p384 or ed25519.",
            )),
        }
    }

    pub fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            PrivateKey::Rsa(_) => AlgorithmIdentifierOwned {
                oid: SHA_256_WITH_RSA_ENCRYPTION,
                parameters: Some(Any::from(AnyRef::NULL)),
            },
            PrivateKey::P256(_) | PrivateKey::P384(_) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            PrivateKey::Ed25519(_) => AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            },
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Rsa(k) => {
                let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(k.clone());
                let sig: rsa::pkcs1v15::Signature = signer.try_sign(message)?;
                Ok(sig.to_vec())
            }
            PrivateKey::P256(k) => {
                let signer = p256::ecdsa::SigningKey::from(k);
                let sig: p256::ecdsa::Signature = signer.sign_prehash(&Sha256::digest(message))?;
                Ok(sig.to_der().to_vec())
            }
            PrivateKey::P384(k) => {
                let signer = p384::ecdsa::SigningKey::from(k);
                let sig: p384::ecdsa::Signature = signer.sign_prehash(&Sha256::digest(message))?;
                Ok(sig.to_der().to_vec())
            }
            PrivateKey::Ed25519(k) => {
                let sig: ed25519_dalek::Signature = k.try_sign(message)?;
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    pub fn facts(&self) -> Result<KeyFacts> {
        self.public_key().facts(true)
    }

    pub fn to_ssh(&self) -> Result<KeypairData> {
        match self {
            PrivateKey::Rsa(k) => Ok(KeypairData::Rsa(RsaKeypair::try_from(k)?)),
            PrivateKey::P256(k) => Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
                public: k.public_key().to_encoded_point(false),
                private: k.clone().into(),
            })),
            PrivateKey::P384(k) => Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
                public: k.public_key().to_encoded_point(false),
                private: k.clone().into(),
            })),
            PrivateKey::Ed25519(k) => Ok(KeypairData::Ed25519(Ed25519Keypair::from(k))),
        }
    }

    pub fn from_ssh(data: &KeypairData) -> Result<Self> {
        match data {
            KeypairData::Rsa(k) => rsa_from_parts(
                &k.public.n,
                &k.public.e,
                &k.private.d,
                &k.private.p,
                &k.private.q,
            ),
            KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => Ok(PrivateKey::P256(
                p256::SecretKey::from_slice(private.as_slice())?,
            )),
            KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => Ok(PrivateKey::P384(
                p384::SecretKey::from_slice(private.as_slice())?,
            )),
            KeypairData::Ed25519(k) => Ok(PrivateKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(k.private.as_ref()),
            )),
            KeypairData::Encrypted(_) => Err(Error::new("The SSH key is still encrypted.")),
            _ => Err(unsupported_algorithm()),
        }
    }

    pub fn to_jwk(&self) -> Result<Jwk> {
        let mut jwk = self.public_key().to_jwk()?;
        match self {
            PrivateKey::Rsa(k) => {
                let p = &k.primes()[0];
                let q = &k.primes()[1];
                let one = BigUint::from(1u8);
                let dp = k.d() % (p - &one);
                let dq = k.d() % (q - &one);
                let qi = k.crt_coefficient().ok_or_else(|| {
                    Error::new("The RSA key's CRT coefficient could not be computed.")
                })?;
                jwk.d = Some(pem::b64url_encode(&k.d().to_bytes_be()));
                jwk.p = Some(pem::b64url_encode(&p.to_bytes_be()));
                jwk.q = Some(pem::b64url_encode(&q.to_bytes_be()));
                jwk.dp = Some(pem::b64url_encode(&dp.to_bytes_be()));
                jwk.dq = Some(pem::b64url_encode(&dq.to_bytes_be()));
                jwk.qi = Some(pem::b64url_encode(&qi.to_bytes_be()));
            }
            PrivateKey::P256(k) => jwk.d = Some(pem::b64url_encode(&k.to_bytes())),
            PrivateKey::P384(k) => jwk.d = Some(pem::b64url_encode(&k.to_bytes())),
            PrivateKey::Ed25519(k) => jwk.d = Some(pem::b64url_encode(&k.to_bytes())),
        }
        Ok(jwk)
    }
}

fn rsa_from_parts(n: &Mpint, e: &Mpint, d: &Mpint, p: &Mpint, q: &Mpint) -> Result<PrivateKey> {
    let big = |m: &Mpint| -> Result<BigUint> {
        m.as_positive_bytes()
            .map(BigUint::from_bytes_be)
            .ok_or_else(|| Error::new("The RSA key holds a negative integer."))
    };
    Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::from_components(
        big(n)?,
        big(e)?,
        big(d)?,
        vec![big(p)?, big(q)?],
    )?))
}

impl PublicKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::from_der(der)?;
        match spki.algorithm.oid {
            RSA_ENCRYPTION => Ok(PublicKey::Rsa(rsa::RsaPublicKey::try_from(spki)?)),
            ID_EC_PUBLIC_KEY => match spki.algorithm.parameters_oid()? {
                SECP_256_R_1 => Ok(PublicKey::P256(p256::PublicKey::try_from(spki)?)),
                SECP_384_R_1 => Ok(PublicKey::P384(p384::PublicKey::try_from(spki)?)),
                _ => Err(unsupported_algorithm()),
            },
            ID_ED_25519 => Ok(PublicKey::Ed25519(ed25519_dalek::VerifyingKey::try_from(
                spki,
            )?)),
            _ => Err(unsupported_algorithm()),
        }
    }

    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let doc = match self {
            PublicKey::Rsa(k) => k.to_public_key_der()?,
            PublicKey::P256(k) => k.to_public_key_der()?,
            PublicKey::P384(k) => k.to_public_key_der()?,
            PublicKey::Ed25519(k) => k.to_public_key_der()?,
        };
        Ok(doc.as_bytes().to_vec())
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            PublicKey::Rsa(_) => "RSA",
            PublicKey::P256(_) | PublicKey::P384(_) => "EC",
            PublicKey::Ed25519(_) => "Ed25519",
        }
    }

    pub fn bits(&self) -> u32 {
        match self {
            PublicKey::Rsa(k) => k.n().bits() as u32,
            PublicKey::P256(_) => 256,
            PublicKey::P384(_) => 384,
            PublicKey::Ed25519(_) => 256,
        }
    }

    pub fn curve(&self) -> Option<String> {
        match self {
            PublicKey::Rsa(_) => None,
            PublicKey::P256(_) => Some("P-256".to_string()),
            PublicKey::P384(_) => Some("P-384".to_string()),
            PublicKey::Ed25519(_) => Some("Ed25519".to_string()),
        }
    }

    pub fn facts(&self, has_private: bool) -> Result<KeyFacts> {
        Ok(KeyFacts {
            algorithm: self.algorithm_name().to_string(),
            bits: self.bits(),
            curve: self.curve(),
            public_key_sha256: spki_sha256_hex(&self.to_spki_der()?),
            has_private,
        })
    }

    pub fn verify(
        &self,
        signature_oid: ObjectIdentifier,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match (self, signature_oid) {
            (PublicKey::Rsa(k), SHA_256_WITH_RSA_ENCRYPTION) => {
                rsa_verify::<Sha256>(k, &Sha256::digest(message), signature)
            }
            (PublicKey::Rsa(k), SHA_384_WITH_RSA_ENCRYPTION) => {
                rsa_verify::<Sha384>(k, &Sha384::digest(message), signature)
            }
            (PublicKey::Rsa(k), SHA_512_WITH_RSA_ENCRYPTION) => {
                rsa_verify::<Sha512>(k, &Sha512::digest(message), signature)
            }
            (PublicKey::Rsa(k), SHA_1_WITH_RSA_ENCRYPTION) => {
                rsa_verify::<Sha1>(k, &Sha1::digest(message), signature)
            }
            (PublicKey::P256(k), oid) => match ecdsa_digest(oid, message) {
                Some(digest) => {
                    let vk = p256::ecdsa::VerifyingKey::from(k);
                    match p256::ecdsa::Signature::from_der(signature) {
                        Ok(sig) => vk.verify_prehash(&digest, &sig).is_ok(),
                        Err(_) => false,
                    }
                }
                None => false,
            },
            (PublicKey::P384(k), oid) => match ecdsa_digest(oid, message) {
                Some(digest) => {
                    let vk = p384::ecdsa::VerifyingKey::from(k);
                    match p384::ecdsa::Signature::from_der(signature) {
                        Ok(sig) => vk.verify_prehash(&digest, &sig).is_ok(),
                        Err(_) => false,
                    }
                }
                None => false,
            },
            (PublicKey::Ed25519(k), ID_ED_25519) => {
                match ed25519_dalek::Signature::from_slice(signature) {
                    Ok(sig) => k.verify(message, &sig).is_ok(),
                    Err(_) => false,
                }
            }
            _ => false,
        }
    }

    pub fn to_ssh(&self) -> Result<KeyData> {
        match self {
            PublicKey::Rsa(k) => Ok(KeyData::Rsa(SshRsaPublicKey {
                e: Mpint::try_from(k.e())?,
                n: Mpint::try_from(k.n())?,
            })),
            PublicKey::P256(k) => Ok(KeyData::Ecdsa(EcdsaPublicKey::NistP256(
                k.to_encoded_point(false),
            ))),
            PublicKey::P384(k) => Ok(KeyData::Ecdsa(EcdsaPublicKey::NistP384(
                k.to_encoded_point(false),
            ))),
            PublicKey::Ed25519(k) => Ok(KeyData::Ed25519(Ed25519PublicKey(k.to_bytes()))),
        }
    }

    pub fn from_ssh(data: &KeyData) -> Result<Self> {
        match data {
            KeyData::Rsa(k) => {
                let big = |m: &Mpint| -> Result<BigUint> {
                    m.as_positive_bytes()
                        .map(BigUint::from_bytes_be)
                        .ok_or_else(|| Error::new("The RSA key holds a negative integer."))
                };
                Ok(PublicKey::Rsa(rsa::RsaPublicKey::new(
                    big(&k.n)?,
                    big(&k.e)?,
                )?))
            }
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => Ok(PublicKey::P256(
                p256::PublicKey::from_sec1_bytes(p.as_bytes())?,
            )),
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(p)) => Ok(PublicKey::P384(
                p384::PublicKey::from_sec1_bytes(p.as_bytes())?,
            )),
            KeyData::Ed25519(k) => Ok(PublicKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(&k.0)
                    .map_err(|_| Error::new("The Ed25519 public key is not a valid point."))?,
            )),
            _ => Err(unsupported_algorithm()),
        }
    }

    pub fn to_jwk(&self) -> Result<Jwk> {
        let mut jwk = Jwk::default();
        match self {
            PublicKey::Rsa(k) => {
                jwk.kty = "RSA".to_string();
                jwk.n = Some(pem::b64url_encode(&k.n().to_bytes_be()));
                jwk.e = Some(pem::b64url_encode(&k.e().to_bytes_be()));
            }
            PublicKey::P256(k) => {
                let point = k.to_encoded_point(false);
                jwk.kty = "EC".to_string();
                jwk.crv = Some("P-256".to_string());
                jwk.x = point.x().map(|x| pem::b64url_encode(x));
                jwk.y = point.y().map(|y| pem::b64url_encode(y));
            }
            PublicKey::P384(k) => {
                let point = k.to_encoded_point(false);
                jwk.kty = "EC".to_string();
                jwk.crv = Some("P-384".to_string());
                jwk.x = point.x().map(|x| pem::b64url_encode(x));
                jwk.y = point.y().map(|y| pem::b64url_encode(y));
            }
            PublicKey::Ed25519(k) => {
                jwk.kty = "OKP".to_string();
                jwk.crv = Some("Ed25519".to_string());
                jwk.x = Some(pem::b64url_encode(k.as_bytes()));
            }
        }
        Ok(jwk)
    }
}

fn rsa_verify<D: Digest + AssociatedOid>(
    key: &rsa::RsaPublicKey,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(key.clone());
    match rsa::pkcs1v15::Signature::try_from(signature) {
        Ok(sig) => vk.verify_prehash(digest, &sig).is_ok(),
        Err(_) => false,
    }
}

fn ecdsa_digest(oid: ObjectIdentifier, message: &[u8]) -> Option<Vec<u8>> {
    match oid {
        ECDSA_WITH_SHA_256 => Some(Sha256::digest(message).to_vec()),
        ECDSA_WITH_SHA_384 => Some(Sha384::digest(message).to_vec()),
        ECDSA_WITH_SHA_512 => Some(Sha512::digest(message).to_vec()),
        _ => None,
    }
}

pub struct ParsedPrivate {
    pub key: Option<PrivateKey>,
    pub encrypted: bool,
}

fn wrong_password() -> Error {
    Error::new("The password is incorrect.")
}

pub fn openssh_private_parse(text: &str, password: &str) -> Result<ParsedPrivate> {
    let parsed = ssh_key::PrivateKey::from_openssh(text)?;
    if parsed.is_encrypted() {
        if password.is_empty() {
            return Ok(ParsedPrivate {
                key: None,
                encrypted: true,
            });
        }
        let decrypted = parsed.decrypt(password).map_err(|_| wrong_password())?;
        return Ok(ParsedPrivate {
            key: Some(PrivateKey::from_ssh(decrypted.key_data())?),
            encrypted: true,
        });
    }
    Ok(ParsedPrivate {
        key: Some(PrivateKey::from_ssh(parsed.key_data())?),
        encrypted: false,
    })
}

pub fn openssh_private_write(key: &PrivateKey, comment: &str, password: &str) -> Result<String> {
    let mut private = ssh_key::PrivateKey::new(key.to_ssh()?, comment)?;
    if !password.is_empty() {
        private = private.encrypt(&mut OsRng, password)?;
    }
    Ok(private.to_openssh(LineEnding::LF)?.to_string())
}

pub fn openssh_public_parse(text: &str) -> Result<PublicKey> {
    let public = ssh_key::PublicKey::from_openssh(text.trim())?;
    PublicKey::from_ssh(public.key_data())
}

pub fn openssh_public_write(key: &PublicKey, comment: &str) -> Result<String> {
    let public = ssh_key::PublicKey::new(key.to_ssh()?, comment);
    let mut text = public.to_openssh()?;
    text.push('\n');
    Ok(text)
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn take_string<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let bad = || Error::new("The PPK private blob is truncated.");
    if *pos + 4 > data.len() {
        return Err(bad());
    }
    let len =
        u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err(bad());
    }
    let out = &data[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

fn put_mpint(out: &mut Vec<u8>, positive: &[u8]) -> Result<()> {
    let m = Mpint::from_positive_bytes(positive)?;
    put_string(out, m.as_bytes());
    Ok(())
}

struct PpkDerived {
    key: [u8; 32],
    iv: [u8; 16],
    mac_key: Vec<u8>,
}

fn ppk_v2_derive(password: &str) -> PpkDerived {
    let mut material = Vec::with_capacity(40);
    for counter in [[0u8, 0, 0, 0], [0u8, 0, 0, 1]] {
        let mut h = Sha1::new();
        h.update(counter);
        h.update(password.as_bytes());
        material.extend_from_slice(&h.finalize());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&material[..32]);
    let mut h = Sha1::new();
    h.update(b"putty-private-key-file-mac-key");
    h.update(password.as_bytes());
    PpkDerived {
        key,
        iv: [0u8; 16],
        mac_key: h.finalize().to_vec(),
    }
}

fn ppk_v3_derive(
    password: &str,
    algorithm: &str,
    memory: u32,
    passes: u32,
    parallelism: u32,
    salt: &[u8],
) -> Result<PpkDerived> {
    let alg = match algorithm {
        "Argon2id" => ArgonAlgorithm::Argon2id,
        "Argon2i" => ArgonAlgorithm::Argon2i,
        "Argon2d" => ArgonAlgorithm::Argon2d,
        _ => {
            return Err(Error::new(
                "The PPK key derivation is not an Argon2 variant.",
            ))
        }
    };
    let params = ArgonParams::new(memory, passes, parallelism, Some(80))?;
    let argon = Argon2::new(alg, ArgonVersion::V0x13, params);
    let mut out = [0u8; 80];
    argon.hash_password_into(password.as_bytes(), salt, &mut out)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&out[32..48]);
    Ok(PpkDerived {
        key,
        iv,
        mac_key: out[48..].to_vec(),
    })
}

fn ppk_mac(version: u8, mac_key: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for f in fields {
        put_string(&mut data, f);
    }
    let bad = |_| Error::new("The PPK MAC key length is not valid.");
    if version == 2 {
        let mut mac = Hmac::<Sha1>::new_from_slice(mac_key).map_err(bad)?;
        mac.update(&data);
        Ok(mac.finalize().into_bytes().to_vec())
    } else {
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).map_err(bad)?;
        mac.update(&data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn aes_cbc(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8], encrypt: bool) -> Result<()> {
    if encrypt {
        let len = buf.len();
        cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded_mut::<NoPadding>(buf, len)
            .map_err(|_| Error::new("The AES-CBC block operation failed."))?;
    } else {
        cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
            .decrypt_padded_mut::<NoPadding>(buf)
            .map_err(|_| Error::new("The AES-CBC block operation failed."))?;
    }
    Ok(())
}

pub fn ppk_parse(text: &str, password: &str) -> Result<ParsedPrivate> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| Error::new("The PPK file is empty."))?;
    let rest = header
        .strip_prefix("PuTTY-User-Key-File-")
        .ok_or_else(|| Error::new("The file does not start with a PuTTY key header."))?;
    let (version_text, algorithm) = rest
        .split_once(": ")
        .ok_or_else(|| Error::new("The PPK header line is malformed."))?;
    let version: u8 = version_text
        .parse()
        .map_err(|_| Error::new("The PPK version is not a number."))?;
    if version != 2 && version != 3 {
        return Err(Error::new("Only PPK versions 2 and 3 are supported."));
    }
    let mut values: Vec<(String, String)> = Vec::new();
    let mut public_blob = Vec::new();
    let mut private_blob = Vec::new();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(": ")
            .ok_or_else(|| Error::new("A PPK line is not a key-value pair."))?;
        if k.ends_with("-Lines") {
            let n: usize = v
                .parse()
                .map_err(|_| Error::new("A PPK line count is not a number."))?;
            let mut body = String::new();
            for _ in 0..n {
                body.push_str(
                    lines
                        .next()
                        .ok_or_else(|| Error::new("The PPK file ended early."))?,
                );
            }
            let decoded = pem::b64_decode(&body)?;
            match k {
                "Public-Lines" => public_blob = decoded,
                "Private-Lines" => private_blob = decoded,
                _ => return Err(Error::new("The PPK file holds an unknown line block.")),
            }
        } else {
            values.push((k.to_string(), v.to_string()));
        }
    }
    let get = |name: &str| -> Option<&str> {
        values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let encryption = get("Encryption").unwrap_or("none").to_string();
    let comment = get("Comment").unwrap_or("").to_string();
    let mac_hex =
        get("Private-MAC").ok_or_else(|| Error::new("The PPK file has no Private-MAC line."))?;
    let expected_mac = pem::unhex(mac_hex)?;
    let encrypted = match encryption.as_str() {
        "none" => false,
        "aes256-cbc" => true,
        _ => return Err(Error::new("The PPK encryption mode is not supported.")),
    };
    if encrypted && password.is_empty() {
        return Ok(ParsedPrivate {
            key: None,
            encrypted: true,
        });
    }
    let derived = if version == 2 {
        ppk_v2_derive(password)
    } else if encrypted {
        let int = |name: &str| -> Result<u32> {
            get(name)
                .ok_or_else(|| Error::new("The PPK file is missing an Argon2 parameter."))?
                .parse()
                .map_err(|_| Error::new("An Argon2 parameter is not a number."))
        };
        let salt = pem::unhex(
            get("Argon2-Salt").ok_or_else(|| Error::new("The PPK file has no Argon2 salt."))?,
        )?;
        ppk_v3_derive(
            password,
            get("Key-Derivation").unwrap_or("Argon2id"),
            int("Argon2-Memory")?,
            int("Argon2-Passes")?,
            int("Argon2-Parallelism")?,
            &salt,
        )?
    } else {
        PpkDerived {
            key: [0u8; 32],
            iv: [0u8; 16],
            mac_key: Vec::new(),
        }
    };
    if encrypted {
        if private_blob.len() % 16 != 0 {
            return Err(Error::new("The PPK private blob is not block aligned."));
        }
        aes_cbc(&derived.key, &derived.iv, &mut private_blob, false)?;
    }
    let mac = ppk_mac(
        version,
        &derived.mac_key,
        &[
            algorithm.as_bytes(),
            encryption.as_bytes(),
            comment.as_bytes(),
            &public_blob,
            &private_blob,
        ],
    )?;
    if mac != expected_mac {
        return Err(if encrypted {
            wrong_password()
        } else {
            Error::new("The PPK file's MAC does not match its contents.")
        });
    }
    let public = ssh_key::PublicKey::from_bytes(&public_blob)?;
    let public_key = PublicKey::from_ssh(public.key_data())?;
    let mut pos = 0usize;
    let key = match public_key {
        PublicKey::Rsa(k) => {
            let d = take_string(&private_blob, &mut pos)?.to_vec();
            let p = take_string(&private_blob, &mut pos)?.to_vec();
            let q = take_string(&private_blob, &mut pos)?.to_vec();
            let big = |b: &[u8]| -> Result<BigUint> {
                Mpint::from_bytes(b)?
                    .as_positive_bytes()
                    .map(BigUint::from_bytes_be)
                    .ok_or_else(|| Error::new("The RSA key holds a negative integer."))
            };
            PrivateKey::Rsa(rsa::RsaPrivateKey::from_components(
                k.n().clone(),
                k.e().clone(),
                big(&d)?,
                vec![big(&p)?, big(&q)?],
            )?)
        }
        PublicKey::P256(_) => {
            let d = Mpint::from_bytes(take_string(&private_blob, &mut pos)?)?;
            let bytes = d
                .as_positive_bytes()
                .ok_or_else(|| Error::new("The EC scalar is negative."))?;
            PrivateKey::P256(p256::SecretKey::from_slice(bytes)?)
        }
        PublicKey::P384(_) => {
            let d = Mpint::from_bytes(take_string(&private_blob, &mut pos)?)?;
            let bytes = d
                .as_positive_bytes()
                .ok_or_else(|| Error::new("The EC scalar is negative."))?;
            PrivateKey::P384(p384::SecretKey::from_slice(bytes)?)
        }
        PublicKey::Ed25519(_) => {
            let raw = take_string(&private_blob, &mut pos)?;
            let m = Mpint::from_bytes(raw)?;
            let bytes = m
                .as_positive_bytes()
                .ok_or_else(|| Error::new("The Ed25519 private scalar is negative."))?;
            if bytes.len() > 32 {
                return Err(Error::new("The Ed25519 private scalar is too long."));
            }
            let mut seed = [0u8; 32];
            seed[32 - bytes.len()..].copy_from_slice(bytes);
            PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
        }
    };
    Ok(ParsedPrivate {
        key: Some(key),
        encrypted,
    })
}

fn wrap64(data: &[u8]) -> Vec<String> {
    let b64 = pem::b64_encode(data);
    b64.as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect()
}

pub fn ppk_write(key: &PrivateKey, comment: &str, password: &str) -> Result<String> {
    let keypair = key.to_ssh()?;
    let algorithm = keypair.algorithm()?.as_str().to_string();
    let public_blob = ssh_key::PublicKey::from(KeyData::try_from(&keypair)?).to_bytes()?;
    let mut private_blob = Vec::new();
    match &keypair {
        KeypairData::Rsa(k) => {
            put_string(&mut private_blob, k.private.d.as_bytes());
            put_string(&mut private_blob, k.private.p.as_bytes());
            put_string(&mut private_blob, k.private.q.as_bytes());
            put_string(&mut private_blob, k.private.iqmp.as_bytes());
        }
        KeypairData::Ecdsa(k) => put_mpint(&mut private_blob, k.private_key_bytes())?,
        KeypairData::Ed25519(k) => put_mpint(&mut private_blob, k.private.as_ref())?,
        _ => return Err(unsupported_algorithm()),
    }
    let encrypted = !password.is_empty();
    let encryption = if encrypted { "aes256-cbc" } else { "none" };
    let mut kdf_lines: Vec<String> = Vec::new();
    let derived = if encrypted {
        let pad = (16 - private_blob.len() % 16) % 16;
        private_blob.extend_from_slice(&random_bytes(pad));
        let salt = random_bytes(16);
        kdf_lines.push("Key-Derivation: Argon2id".to_string());
        kdf_lines.push("Argon2-Memory: 8192".to_string());
        kdf_lines.push("Argon2-Passes: 13".to_string());
        kdf_lines.push("Argon2-Parallelism: 1".to_string());
        kdf_lines.push(format!("Argon2-Salt: {}", pem::hex(&salt)));
        ppk_v3_derive(password, "Argon2id", 8192, 13, 1, &salt)?
    } else {
        PpkDerived {
            key: [0u8; 32],
            iv: [0u8; 16],
            mac_key: Vec::new(),
        }
    };
    let mac = ppk_mac(
        3,
        &derived.mac_key,
        &[
            algorithm.as_bytes(),
            encryption.as_bytes(),
            comment.as_bytes(),
            &public_blob,
            &private_blob,
        ],
    )?;
    if encrypted {
        aes_cbc(&derived.key, &derived.iv, &mut private_blob, true)?;
    }
    let mut out = String::new();
    out.push_str(&format!("PuTTY-User-Key-File-3: {}\n", algorithm));
    out.push_str(&format!("Encryption: {}\n", encryption));
    out.push_str(&format!("Comment: {}\n", comment));
    let public_lines = wrap64(&public_blob);
    out.push_str(&format!("Public-Lines: {}\n", public_lines.len()));
    for l in public_lines {
        out.push_str(&l);
        out.push('\n');
    }
    for l in kdf_lines {
        out.push_str(&l);
        out.push('\n');
    }
    let private_lines = wrap64(&private_blob);
    out.push_str(&format!("Private-Lines: {}\n", private_lines.len()));
    for l in private_lines {
        out.push_str(&l);
        out.push('\n');
    }
    out.push_str(&format!("Private-MAC: {}\n", pem::hex(&mac)));
    Ok(out)
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

pub fn json_stringify<T: Serialize>(value: &T) -> Result<String> {
    let js = serde_wasm_bindgen::to_value(value)?;
    let text =
        js_sys::JSON::stringify_with_replacer_and_space(&js, &JsValue::NULL, &JsValue::from(2))
            .map_err(|_| Error::new("The JSON document could not be written."))?;
    let mut out: String = text.into();
    out.push('\n');
    Ok(out)
}

pub struct ParsedJwk {
    pub public: PublicKey,
    pub private: Option<PrivateKey>,
}

pub fn jwk_parse(text: &str) -> Result<ParsedJwk> {
    let js = js_sys::JSON::parse(text).map_err(|_| Error::new("The text is not valid JSON."))?;
    let jwk: Jwk = match serde_wasm_bindgen::from_value::<Jwks>(js.clone()) {
        Ok(set) if !set.keys.is_empty() => set.keys.into_iter().next().unwrap_or_default(),
        _ => serde_wasm_bindgen::from_value(js)?,
    };
    let field = |v: &Option<String>, name: &str| -> Result<Vec<u8>> {
        pem::b64url_decode(
            v.as_deref()
                .ok_or_else(|| Error::new(format!("The JWK is missing its {} member.", name)))?,
        )
    };
    match jwk.kty.as_str() {
        "RSA" => {
            let n = BigUint::from_bytes_be(&field(&jwk.n, "n")?);
            let e = BigUint::from_bytes_be(&field(&jwk.e, "e")?);
            let public = PublicKey::Rsa(rsa::RsaPublicKey::new(n.clone(), e.clone())?);
            let private = match &jwk.d {
                Some(_) => {
                    let d = BigUint::from_bytes_be(&field(&jwk.d, "d")?);
                    let primes = match (&jwk.p, &jwk.q) {
                        (Some(_), Some(_)) => vec![
                            BigUint::from_bytes_be(&field(&jwk.p, "p")?),
                            BigUint::from_bytes_be(&field(&jwk.q, "q")?),
                        ],
                        _ => Vec::new(),
                    };
                    Some(PrivateKey::Rsa(rsa::RsaPrivateKey::from_components(
                        n, e, d, primes,
                    )?))
                }
                None => None,
            };
            Ok(ParsedJwk { public, private })
        }
        "EC" => {
            let x = field(&jwk.x, "x")?;
            let y = field(&jwk.y, "y")?;
            let mut point = vec![0x04u8];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            match jwk.crv.as_deref() {
                Some("P-256") => {
                    let public = PublicKey::P256(p256::PublicKey::from_sec1_bytes(&point)?);
                    let private = match &jwk.d {
                        Some(_) => Some(PrivateKey::P256(p256::SecretKey::from_slice(&field(
                            &jwk.d, "d",
                        )?)?)),
                        None => None,
                    };
                    Ok(ParsedJwk { public, private })
                }
                Some("P-384") => {
                    let public = PublicKey::P384(p384::PublicKey::from_sec1_bytes(&point)?);
                    let private = match &jwk.d {
                        Some(_) => Some(PrivateKey::P384(p384::SecretKey::from_slice(&field(
                            &jwk.d, "d",
                        )?)?)),
                        None => None,
                    };
                    Ok(ParsedJwk { public, private })
                }
                _ => Err(Error::new("The JWK curve must be P-256 or P-384.")),
            }
        }
        "OKP" => {
            if jwk.crv.as_deref() != Some("Ed25519") {
                return Err(Error::new("The JWK OKP curve must be Ed25519."));
            }
            let x = field(&jwk.x, "x")?;
            let x_arr: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("The Ed25519 public key must be 32 bytes."))?;
            let public = PublicKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(&x_arr)
                    .map_err(|_| Error::new("The Ed25519 public key is not a valid point."))?,
            );
            let private = match &jwk.d {
                Some(_) => {
                    let d = field(&jwk.d, "d")?;
                    let seed: [u8; 32] = d
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::new("The Ed25519 private key must be 32 bytes."))?;
                    Some(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                        &seed,
                    )))
                }
                None => None,
            };
            Ok(ParsedJwk { public, private })
        }
        _ => Err(Error::new("The JWK key type must be RSA, EC or OKP.")),
    }
}
