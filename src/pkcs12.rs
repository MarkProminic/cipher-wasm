use crate::error::{Error, Result};
use crate::keys::{random_bytes, PrivateKey, PBKDF2_ITERATIONS};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, InnerIvInit, KeyIvInit};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::encrypted_data::EncryptedData;
use cms::enveloped_data::EncryptedContentInfo;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use const_oid::db::rfc5912::{ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, AnyRef, BmpString, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence};
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use hmac::{Mac, SimpleHmac};
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use pkcs12::mac_data::MacData;
use pkcs12::pbe_params::{EncryptedPrivateKeyInfo, Pkcs12PbeParams};
use pkcs12::pfx::{Pfx, Version};
use pkcs12::{
    PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID, PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC,
    PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC, PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC,
    PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
};
use pkcs5::pbes2;
use pkcs8::PrivateKeyInfo;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};

const FRIENDLY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
const MAC_ITERATIONS: i32 = 2048;

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SafeBag {
    bag_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    bag_value: Any,
    bag_attributes: Option<Attributes>,
}

type SafeContents = Vec<SafeBag>;

pub struct Contents {
    pub certs: Vec<Vec<u8>>,
    pub keys: Vec<PrivateKey>,
    pub needs_password: bool,
}

fn wrong_password() -> Error {
    Error::new("The password is incorrect.")
}

fn pkcs12_mac<D>(password: &str, salt: &[u8], iterations: i32, data: &[u8]) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset + BlockSizeUser + Clone,
{
    let key = derive_key_utf8::<D>(password, salt, Pkcs12KeyType::Mac, iterations, <D as Digest>::output_size())?;
    let mut mac = SimpleHmac::<D>::new_from_slice(&key)
        .map_err(|_| Error::new("The MAC key length is not valid."))?;
    Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn mac_for(oid: ObjectIdentifier, password: &str, salt: &[u8], iterations: i32, data: &[u8]) -> Result<Vec<u8>> {
    match oid {
        ID_SHA_1 => pkcs12_mac::<Sha1>(password, salt, iterations, data),
        ID_SHA_256 => pkcs12_mac::<Sha256>(password, salt, iterations, data),
        ID_SHA_384 => pkcs12_mac::<Sha384>(password, salt, iterations, data),
        ID_SHA_512 => pkcs12_mac::<Sha512>(password, salt, iterations, data),
        _ => Err(Error::new("The PFX MAC digest algorithm is not supported.")),
    }
}

fn pbe1_key_iv(oid: ObjectIdentifier, params: &Pkcs12PbeParams, password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_len = match oid {
        PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => 24,
        PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC => 16,
        PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC => 5,
        PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC => 16,
        _ => return Err(Error::new("The PFX encryption scheme is not supported.")),
    };
    let salt = params.salt.as_bytes();
    let key = derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::EncryptionKey, params.iterations, key_len)?;
    let iv = derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::Iv, params.iterations, 8)?;
    Ok((key, iv))
}

fn pbe1_decrypt(oid: ObjectIdentifier, params: &Pkcs12PbeParams, password: &str, ct: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = pbe1_key_iv(oid, params, password)?;
    let bad = |_| wrong_password();
    let bad_key = |_| Error::new("The derived key length is not valid.");
    match oid {
        PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .map_err(bad_key)?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(bad),
        PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC => cbc::Decryptor::<des::TdesEde2>::new_from_slices(&key, &iv)
            .map_err(bad_key)?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(bad),
        PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC => {
            cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(rc2::Rc2::new_with_eff_key_len(&key, 40), &iv)
                .map_err(bad_key)?
                .decrypt_padded_vec_mut::<Pkcs7>(ct)
                .map_err(bad)
        }
        PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC => {
            cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(rc2::Rc2::new_with_eff_key_len(&key, 128), &iv)
                .map_err(bad_key)?
                .decrypt_padded_vec_mut::<Pkcs7>(ct)
                .map_err(bad)
        }
        _ => Err(Error::new("The PFX encryption scheme is not supported.")),
    }
}

fn pbe1_encrypt(oid: ObjectIdentifier, params: &Pkcs12PbeParams, password: &str, pt: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = pbe1_key_iv(oid, params, password)?;
    let bad_key = |_| Error::new("The derived key length is not valid.");
    match oid {
        PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => Ok(cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .map_err(bad_key)?
            .encrypt_padded_vec_mut::<Pkcs7>(pt)),
        PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC => Ok(cbc::Encryptor::<rc2::Rc2>::inner_iv_slice_init(
            rc2::Rc2::new_with_eff_key_len(&key, 40),
            &iv,
        )
        .map_err(bad_key)?
        .encrypt_padded_vec_mut::<Pkcs7>(pt)),
        _ => Err(Error::new("The PFX encryption scheme is not supported.")),
    }
}

fn decrypt(alg: &AlgorithmIdentifierOwned, password: &str, ct: &[u8]) -> Result<Vec<u8>> {
    if alg.oid == pbes2::PBES2_OID {
        let der = alg.to_der()?;
        let scheme = pkcs5::EncryptionScheme::try_from(der.as_slice())?;
        return scheme.decrypt(password.as_bytes(), ct).map_err(|_| wrong_password());
    }
    let params: Pkcs12PbeParams = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Error::new("The PFX encryption scheme has no parameters."))?
        .decode_as()?;
    pbe1_decrypt(alg.oid, &params, password, ct)
}

pub fn is_pfx(bytes: &[u8]) -> bool {
    Pfx::from_der(bytes).is_ok()
}

pub fn is_encrypted_private_key(bytes: &[u8]) -> bool {
    EncryptedPrivateKeyInfo::from_der(bytes).is_ok()
}

pub fn decrypt_private_key(der: &[u8], password: &str) -> Result<Vec<u8>> {
    let info = EncryptedPrivateKeyInfo::from_der(der)
        .map_err(|_| Error::new("The data is not an encrypted PKCS#8 private key."))?;
    decrypt(&info.encryption_algorithm, password, info.encrypted_data.as_bytes())
}

fn bags_from(ci: &ContentInfo, password: &str) -> Result<SafeContents> {
    match ci.content_type {
        ID_DATA => {
            let octets: OctetString = ci.content.decode_as()?;
            Ok(SafeContents::from_der(octets.as_bytes())?)
        }
        ID_ENCRYPTED_DATA => {
            let ed: EncryptedData = ci.content.decode_as()?;
            let ct = ed
                .enc_content_info
                .encrypted_content
                .ok_or_else(|| Error::new("The PFX encrypted content is detached."))?;
            let pt = decrypt(&ed.enc_content_info.content_enc_alg, password, ct.as_bytes())?;
            Ok(SafeContents::from_der(&pt)?)
        }
        _ => Err(Error::new("The PFX holds a content type that is not supported.")),
    }
}

pub fn read(der: &[u8], password: &str) -> Result<Contents> {
    let pfx = Pfx::from_der(der).map_err(|_| Error::new("The data is not a PKCS#12 PFX."))?;
    if pfx.auth_safe.content_type != ID_DATA {
        return Err(Error::new("The PFX is protected by a public key, which is not supported."));
    }
    let auth: OctetString = pfx.auth_safe.content.decode_as()?;
    let auth_bytes = auth.as_bytes();
    let locked = Contents { certs: Vec::new(), keys: Vec::new(), needs_password: true };
    if let Some(mac) = &pfx.mac_data {
        let computed = mac_for(mac.mac.algorithm.oid, password, mac.mac_salt.as_bytes(), mac.iterations, auth_bytes)?;
        if computed != mac.mac.digest.as_bytes() {
            return if password.is_empty() { Ok(locked) } else { Err(wrong_password()) };
        }
    }
    let infos: Vec<ContentInfo> = Vec::from_der(auth_bytes)?;
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for ci in &infos {
        let bags = match bags_from(ci, password) {
            Ok(b) => b,
            Err(e) => {
                return if password.is_empty() && e.0 == wrong_password().0 { Ok(locked) } else { Err(e) };
            }
        };
        for bag in bags {
            match bag.bag_id {
                PKCS_12_CERT_BAG_OID => {
                    let cert: CertBag = bag.bag_value.decode_as()?;
                    if cert.cert_id == PKCS_12_X509_CERT_OID {
                        certs.push(cert.cert_value.as_bytes().to_vec());
                    }
                }
                PKCS_12_KEY_BAG_OID => {
                    keys.push(PrivateKey::from_pkcs8_der(&bag.bag_value.to_der()?)?);
                }
                PKCS_12_PKCS8_KEY_BAG_OID => {
                    let epki: EncryptedPrivateKeyInfo = bag.bag_value.decode_as()?;
                    let pt = match decrypt(&epki.encryption_algorithm, password, epki.encrypted_data.as_bytes()) {
                        Ok(pt) => pt,
                        Err(e) => {
                            return if password.is_empty() && e.0 == wrong_password().0 { Ok(locked) } else { Err(e) };
                        }
                    };
                    keys.push(PrivateKey::from_pkcs8_der(&pt)?);
                }
                _ => {}
            }
        }
    }
    Ok(Contents { certs, keys, needs_password: false })
}

fn attributes(friendly_name: &str, key_id: &[u8]) -> Result<Attributes> {
    let mut set: SetOfVec<Attribute> = SetOfVec::new();
    if !friendly_name.is_empty() {
        let mut values = SetOfVec::new();
        values.insert(Any::encode_from(&BmpString::from_utf8(friendly_name)?)?)?;
        set.insert(Attribute { oid: FRIENDLY_NAME, values })?;
    }
    let mut values = SetOfVec::new();
    values.insert(Any::encode_from(&OctetString::new(key_id)?)?)?;
    set.insert(Attribute { oid: LOCAL_KEY_ID, values })?;
    Ok(set)
}

fn pbes2_params<'a>(salt: &'a [u8], iv: &'a [u8; 16]) -> Result<pbes2::Parameters<'a>> {
    Ok(pbes2::Parameters::pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, salt, iv)?)
}

fn pbes2_algorithm(params: &pbes2::Parameters<'_>) -> Result<AlgorithmIdentifierOwned> {
    let der = pkcs5::EncryptionScheme::Pbes2(params.clone()).to_der()?;
    Ok(AlgorithmIdentifierOwned::from_der(&der)?)
}

fn pbe1_algorithm(oid: ObjectIdentifier, params: &Pkcs12PbeParams) -> Result<AlgorithmIdentifierOwned> {
    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::encode_from(params)?),
    })
}

fn encrypted_data(alg: AlgorithmIdentifierOwned, ct: Vec<u8>) -> Result<ContentInfo> {
    let ed = EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: EncryptedContentInfo {
            content_type: ID_DATA,
            content_enc_alg: alg,
            encrypted_content: Some(OctetString::new(ct)?),
        },
        unprotected_attrs: None,
    };
    Ok(ContentInfo {
        content_type: ID_ENCRYPTED_DATA,
        content: Any::encode_from(&ed)?,
    })
}

fn data_content(bytes: Vec<u8>) -> Result<ContentInfo> {
    Ok(ContentInfo {
        content_type: ID_DATA,
        content: Any::encode_from(&OctetString::new(bytes)?)?,
    })
}

pub fn write(certs: &[Vec<u8>], key: Option<&PrivateKey>, password: &str, legacy: bool, friendly_name: &str) -> Result<Vec<u8>> {
    if certs.is_empty() && key.is_none() {
        return Err(Error::new("A PFX needs at least one certificate or a private key."));
    }
    let key_spki = match key {
        Some(k) => Some(k.public_key().to_spki_der()?),
        None => None,
    };
    let key_id: Vec<u8> = match &key_spki {
        Some(spki) => sha1::Sha1::digest(spki).to_vec(),
        None => sha1::Sha1::digest(certs.first().map(|c| c.as_slice()).unwrap_or(&[])).to_vec(),
    };
    let mut infos: Vec<ContentInfo> = Vec::new();
    if !certs.is_empty() {
        let mut bags: SafeContents = Vec::new();
        let mut tagged = false;
        for der in certs {
            let cert = x509_cert::Certificate::from_der(der)?;
            let matches = match &key_spki {
                Some(spki) => cert.tbs_certificate.subject_public_key_info.to_der()? == *spki,
                None => !tagged,
            };
            let attrs = if matches && !tagged {
                tagged = true;
                Some(attributes(friendly_name, &key_id)?)
            } else {
                None
            };
            bags.push(SafeBag {
                bag_id: PKCS_12_CERT_BAG_OID,
                bag_value: Any::encode_from(&CertBag {
                    cert_id: PKCS_12_X509_CERT_OID,
                    cert_value: OctetString::new(der.clone())?,
                })?,
                bag_attributes: attrs,
            });
        }
        let plain = bags.to_der()?;
        let ci = if legacy {
            let params = Pkcs12PbeParams { salt: OctetString::new(random_bytes(8))?, iterations: MAC_ITERATIONS };
            let ct = pbe1_encrypt(PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC, &params, password, &plain)?;
            encrypted_data(pbe1_algorithm(PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC, &params)?, ct)?
        } else {
            let salt = random_bytes(16);
            let iv_vec = random_bytes(16);
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_vec);
            let params = pbes2_params(&salt, &iv)?;
            let ct = params.encrypt(password.as_bytes(), &plain)?;
            encrypted_data(pbes2_algorithm(&params)?, ct)?
        };
        infos.push(ci);
    }
    if let Some(k) = key {
        let pkcs8 = k.to_pkcs8_der()?;
        let epki_der = if legacy {
            let params = Pkcs12PbeParams { salt: OctetString::new(random_bytes(8))?, iterations: MAC_ITERATIONS };
            let ct = pbe1_encrypt(PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC, &params, password, &pkcs8)?;
            EncryptedPrivateKeyInfo {
                encryption_algorithm: pbe1_algorithm(PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC, &params)?,
                encrypted_data: OctetString::new(ct)?,
            }
            .to_der()?
        } else {
            let salt = random_bytes(16);
            let iv_vec = random_bytes(16);
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_vec);
            let params = pbes2_params(&salt, &iv)?;
            let info = PrivateKeyInfo::from_der(&pkcs8)?;
            info.encrypt_with_params(params, password.as_bytes())?.as_bytes().to_vec()
        };
        let bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: Any::from_der(&epki_der)?,
            bag_attributes: Some(attributes(friendly_name, &key_id)?),
        };
        infos.push(data_content(vec![bag].to_der()?)?);
    }
    let auth_bytes = infos.to_der()?;
    let mac_salt = random_bytes(8);
    let (mac_oid, digest) = if legacy {
        (ID_SHA_1, mac_for(ID_SHA_1, password, &mac_salt, MAC_ITERATIONS, &auth_bytes)?)
    } else {
        (ID_SHA_256, mac_for(ID_SHA_256, password, &mac_salt, MAC_ITERATIONS, &auth_bytes)?)
    };
    let pfx = Pfx {
        version: Version::V3,
        auth_safe: data_content(auth_bytes)?,
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned {
                    oid: mac_oid,
                    parameters: Some(Any::from(AnyRef::NULL)),
                },
                digest: OctetString::new(digest)?,
            },
            mac_salt: OctetString::new(mac_salt)?,
            iterations: MAC_ITERATIONS,
        }),
    };
    Ok(pfx.to_der()?)
}
