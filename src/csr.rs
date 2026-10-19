use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey, Scheme};
use crate::x509::{self, Facts, NameMap, San};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::asn1::{BitString, SetOfVec};
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};

pub fn parse(der: &[u8]) -> Result<CertReq> {
    CertReq::from_der(der).map_err(|_| Error::new("The data is not a PKCS#10 certificate request."))
}

pub fn public_key_of(req: &CertReq) -> Result<PublicKey> {
    PublicKey::from_spki_der(&req.info.public_key.to_der()?)
}

pub fn verify(req: &CertReq) -> bool {
    let key = match public_key_of(req) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let info = match req.info.to_der() {
        Ok(i) => i,
        Err(_) => return false,
    };
    key.verify(&req.algorithm, &info, req.signature.raw_bytes())
}

pub fn extensions(req: &CertReq) -> Vec<Extension> {
    for attr in req.info.attributes.iter() {
        if attr.oid == ID_EXTENSION_REQ {
            for value in attr.values.iter() {
                if let Ok(exts) = value.decode_as::<Vec<Extension>>() {
                    return exts;
                }
            }
        }
    }
    Vec::new()
}

pub fn facts(der: &[u8]) -> Result<Facts> {
    let req = parse(der)?;
    let key = public_key_of(&req)?;
    let exts = extensions(&req);
    let (is_ca, path_len) = x509::extension_basic_constraints(&exts);
    let fp = x509::fingerprints(der);
    Ok(Facts {
        subject: x509::name_map(&req.info.subject),
        issuer: NameMap(Vec::new()),
        subject_dn: x509::name_string(&req.info.subject),
        issuer_dn: String::new(),
        serial_hex: String::new(),
        not_before: String::new(),
        not_after: String::new(),
        algorithm: key.algorithm_name().to_string(),
        bits: key.bits(),
        curve: key.curve(),
        signature_algorithm: x509::signature_name(&req.algorithm.oid),
        self_signed: false,
        is_ca,
        path_len,
        sans: x509::extension_sans(&exts),
        key_usage: x509::extension_key_usage(&exts),
        ext_key_usage: x509::extension_eku(&exts),
        fingerprint_sha256: fp.sha256,
        fingerprint_sha1: fp.sha1,
        fingerprint_md5: fp.md5,
        subject_key_id: None,
        authority_key_id: None,
        csr_signature_valid: Some(verify(&req)),
    })
}

pub fn build(
    key: &PrivateKey,
    scheme: Scheme,
    subject: &NameMap,
    sans: &[San],
    eku: &[String],
) -> Result<Vec<u8>> {
    let subject = x509::name_from_map(subject)?;
    let public_key = SubjectPublicKeyInfoOwned::from_der(&key.public_key().to_spki_der()?)?;
    let mut attributes: SetOfVec<Attribute> = SetOfVec::new();
    let mut exts: Vec<Extension> = Vec::new();
    if !sans.is_empty() {
        let names = sans
            .iter()
            .map(x509::san_to_general_name)
            .collect::<Result<Vec<_>>>()?;
        let san = SubjectAltName(names);
        let ext = (&san).to_extension(&subject, &exts)?;
        exts.push(ext);
    }
    if !eku.is_empty() {
        let oids = eku
            .iter()
            .map(|n| x509::eku_oid(n))
            .collect::<Result<Vec<_>>>()?;
        let eku = ExtendedKeyUsage(oids);
        let ext = (&eku).to_extension(&subject, &exts)?;
        exts.push(ext);
    }
    if !exts.is_empty() {
        attributes.insert(Attribute::try_from(ExtensionReq(exts))?)?;
    }
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes,
    };
    let signature = key.sign(scheme, &info.to_der()?)?;
    let req = CertReq {
        info,
        algorithm: key.signature_algorithm(scheme)?,
        signature: BitString::from_bytes(&signature)?,
    };
    Ok(req.to_der()?)
}
