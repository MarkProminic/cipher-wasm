use crate::csr;
use crate::error::{Error, Result};
use crate::keys::{random_bytes, PrivateKey, PublicKey};
use crate::x509::{self, NameMap, San};
use const_oid::AssociatedOid;
use der::asn1::{BitString, GeneralizedTime, OctetString, UtcTime};
use der::{DateTime, Decode, Encode};
use sha1::{Digest, Sha1};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate};

pub struct Issue<'a> {
    pub signer: &'a PrivateKey,
    pub issuer_name: Name,
    pub issuer_key: &'a PublicKey,
    pub subject: Name,
    pub subject_key: &'a PublicKey,
    pub days: u32,
    pub is_ca: bool,
    pub path_len: Option<u8>,
    pub sans: Vec<San>,
    pub eku: Vec<String>,
    pub extra: Vec<Extension>,
}

fn time_from_secs(secs: u64) -> Result<Time> {
    let dt = DateTime::from_unix_duration(core::time::Duration::from_secs(secs))
        .map_err(|_| Error::new("The validity period falls outside the dates a certificate can hold."))?;
    if dt.year() <= UtcTime::MAX_YEAR {
        Ok(Time::UtcTime(UtcTime::from_date_time(dt)?))
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(dt)))
    }
}

fn now_secs() -> u64 {
    let ms = js_sys::Date::now();
    if ms.is_finite() && ms > 0.0 {
        (ms / 1000.0) as u64
    } else {
        0
    }
}

fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec()
}

pub fn issue(p: Issue<'_>) -> Result<Vec<u8>> {
    if p.days == 0 {
        return Err(Error::new("The validity in days must be at least one."));
    }
    let mut serial = random_bytes(20);
    serial[0] &= 0x7f;
    if serial.iter().all(|b| *b == 0) {
        serial[19] = 1;
    }
    let serial_number = SerialNumber::new(&serial)?;
    let start = now_secs();
    let end = start
        .checked_add(u64::from(p.days) * 86_400)
        .ok_or_else(|| Error::new("The validity period is too long."))?;
    let validity = Validity {
        not_before: time_from_secs(start)?,
        not_after: time_from_secs(end)?,
    };
    let subject_spki = SubjectPublicKeyInfoOwned::from_der(&p.subject_key.to_spki_der()?)?;
    let issuer_spki = SubjectPublicKeyInfoOwned::from_der(&p.issuer_key.to_spki_der()?)?;
    let mut exts: Vec<Extension> = Vec::new();
    exts.push(SubjectKeyIdentifier(OctetString::new(key_identifier(&subject_spki))?).to_extension(&p.subject, &exts)?);
    exts.push(
        AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(key_identifier(&issuer_spki))?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        }
        .to_extension(&p.subject, &exts)?,
    );
    exts.push(
        BasicConstraints {
            ca: p.is_ca,
            path_len_constraint: if p.is_ca { p.path_len } else { None },
        }
        .to_extension(&p.subject, &exts)?,
    );
    let usage = if p.is_ca {
        KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature
    } else {
        match p.subject_key {
            PublicKey::Rsa(_) => KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment,
            _ => KeyUsages::DigitalSignature.into(),
        }
    };
    exts.push(KeyUsage(usage).to_extension(&p.subject, &exts)?);
    if !p.sans.is_empty() {
        let names = p.sans.iter().map(x509::san_to_general_name).collect::<Result<Vec<_>>>()?;
        exts.push(SubjectAltName(names).to_extension(&p.subject, &exts)?);
    }
    if !p.eku.is_empty() {
        let oids = p.eku.iter().map(|n| x509::eku_oid(n)).collect::<Result<Vec<_>>>()?;
        exts.push(ExtendedKeyUsage(oids).to_extension(&p.subject, &exts)?);
    }
    let reserved = [
        SubjectKeyIdentifier::OID,
        AuthorityKeyIdentifier::OID,
        BasicConstraints::OID,
        KeyUsage::OID,
        SubjectAltName::OID,
        ExtendedKeyUsage::OID,
    ];
    for e in p.extra {
        if !reserved.contains(&e.extn_id) {
            exts.push(e);
        }
    }
    let signature_algorithm = p.signer.signature_algorithm();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: signature_algorithm.clone(),
        issuer: p.issuer_name,
        validity,
        subject: p.subject,
        subject_public_key_info: subject_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(exts),
    };
    let signature = p.signer.sign(&tbs.to_der()?)?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature: BitString::from_bytes(&signature)?,
    };
    Ok(cert.to_der()?)
}

pub fn self_sign(
    key_der: &[u8],
    subject: &NameMap,
    sans: Vec<San>,
    eku: Vec<String>,
    days: u32,
    is_ca: bool,
    path_len: Option<u8>,
) -> Result<Vec<u8>> {
    let key = PrivateKey::from_pkcs8_der(key_der)?;
    let public = key.public_key();
    let name = x509::name_from_map(subject)?;
    issue(Issue {
        signer: &key,
        issuer_name: name.clone(),
        issuer_key: &public,
        subject: name,
        subject_key: &public,
        days,
        is_ca,
        path_len,
        sans,
        eku,
        extra: Vec::new(),
    })
}

pub fn sign_csr(
    csr_der: &[u8],
    ca_cert_der: &[u8],
    ca_key_der: &[u8],
    days: u32,
    is_ca: bool,
    path_len: Option<u8>,
    copy_extensions: bool,
) -> Result<Vec<u8>> {
    let req = csr::parse(csr_der)?;
    if !csr::verify(&req) {
        return Err(Error::new("The certificate request's signature is not valid."));
    }
    let ca_cert = x509::parse(ca_cert_der)?;
    let ca_key = PrivateKey::from_pkcs8_der(ca_key_der)?;
    let ca_public = ca_key.public_key();
    if ca_public.to_spki_der()? != x509::spki_der(&ca_cert)? {
        return Err(Error::new("The CA key does not match the CA certificate."));
    }
    let subject_key = csr::public_key_of(&req)?;
    let (sans, eku, extra) = if copy_extensions {
        let exts = csr::extensions(&req);
        (x509::extension_sans(&exts), x509::extension_eku(&exts), exts)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    issue(Issue {
        signer: &ca_key,
        issuer_name: ca_cert.tbs_certificate.subject.clone(),
        issuer_key: &ca_public,
        subject: req.info.subject.clone(),
        subject_key: &subject_key,
        days,
        is_ca,
        path_len,
        sans,
        eku,
        extra,
    })
}
