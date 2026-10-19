use crate::error::{Error, Result};
use crate::keys::{spki_sha256_hex, PublicKey};
use crate::pem;
use const_oid::db::rfc5280::{
    ANY_EXTENDED_KEY_USAGE, ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION,
    ID_KP_OCSP_SIGNING, ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING,
};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_RSASSA_PSS,
    MD_5_WITH_RSA_ENCRYPTION, SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc8410::{ID_ED_25519, ID_ED_448};
use const_oid::db::DB;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{Any, Ia5String, OctetString};
use der::{DateTime, Decode, Encode, Tag, Tagged};
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::time::Time;
use x509_cert::Certificate;

#[derive(Clone, Debug, Default)]
pub struct NameMap(pub Vec<(String, String)>);

impl Serialize for NameMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

struct NameMapVisitor;

impl<'de> Visitor<'de> for NameMapVisitor {
    type Value = NameMap;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("an object of short names to strings")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut access: A,
    ) -> core::result::Result<NameMap, A::Error> {
        let mut out = Vec::new();
        while let Some((k, v)) = access.next_entry::<String, String>()? {
            out.push((k, v));
        }
        Ok(NameMap(out))
    }
}

impl<'de> Deserialize<'de> for NameMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_map(NameMapVisitor)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct San {
    pub kind: String,
    pub value: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Facts {
    pub subject: NameMap,
    pub issuer: NameMap,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub algorithm: String,
    pub bits: u32,
    pub curve: Option<String>,
    pub signature_algorithm: String,
    pub self_signed: bool,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub sans: Vec<San>,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub fingerprint_md5: String,
    pub subject_key_id: Option<String>,
    pub authority_key_id: Option<String>,
    pub csr_signature_valid: Option<bool>,
}

pub fn parse(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|_| Error::new("The data is not an X.509 certificate."))
}

pub fn attribute_value_string(value: &Any) -> String {
    match value.tag() {
        Tag::Utf8String
        | Tag::PrintableString
        | Tag::Ia5String
        | Tag::TeletexString
        | Tag::VisibleString => String::from_utf8_lossy(value.value()).to_string(),
        Tag::BmpString => {
            let units: Vec<u16> = value
                .value()
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => format!("#{}", pem::hex(value.value())),
    }
}

pub fn short_name(oid: &ObjectIdentifier) -> String {
    let mut best: Option<&str> = None;
    for n in DB.find_names_for_oid(*oid) {
        if best.map(|b| n.len() < b.len()).unwrap_or(true) {
            best = Some(n);
        }
    }
    match best {
        Some(n) => n.to_ascii_uppercase(),
        None => oid.to_string(),
    }
}

pub fn name_map(name: &Name) -> NameMap {
    let mut out: Vec<(String, String)> = Vec::new();
    for rdn in name.iter_rdn() {
        for atv in rdn.iter() {
            let key = short_name(&atv.oid);
            let value = attribute_value_string(&atv.value);
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => {
                    entry.1.push(',');
                    entry.1.push_str(&value);
                }
                None => out.push((key, value)),
            }
        }
    }
    NameMap(out)
}

pub fn name_string(name: &Name) -> String {
    name.to_string()
}

pub fn name_from_map(map: &NameMap) -> Result<Name> {
    let mut rdns = RdnSequence::default();
    for (key, value) in &map.0 {
        let oid = match DB.by_name(key) {
            Some(oid) => *oid,
            None => ObjectIdentifier::new(key).map_err(|_| {
                Error::new(format!(
                    "The subject attribute {} is not a known name or an OID.",
                    key
                ))
            })?,
        };
        let upper = key.to_ascii_uppercase();
        let printable = value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
        let tag = if (upper == "C" || upper == "SERIALNUMBER") && printable {
            Tag::PrintableString
        } else if upper == "DC" {
            Tag::Ia5String
        } else {
            Tag::Utf8String
        };
        let atv = AttributeTypeAndValue {
            oid,
            value: Any::new(tag, value.as_bytes())?,
        };
        rdns.push(RelativeDistinguishedName::try_from(vec![atv])?);
    }
    Ok(Name::from_der(&rdns.to_der()?)?)
}

pub fn time_string(time: &Time) -> String {
    time.to_date_time().to_string()
}

pub fn date_string(dt: &DateTime) -> String {
    dt.to_string()
}

pub fn signature_name(oid: &ObjectIdentifier) -> String {
    match *oid {
        SHA_256_WITH_RSA_ENCRYPTION => "sha256WithRSAEncryption".to_string(),
        SHA_384_WITH_RSA_ENCRYPTION => "sha384WithRSAEncryption".to_string(),
        SHA_512_WITH_RSA_ENCRYPTION => "sha512WithRSAEncryption".to_string(),
        SHA_224_WITH_RSA_ENCRYPTION => "sha224WithRSAEncryption".to_string(),
        SHA_1_WITH_RSA_ENCRYPTION => "sha1WithRSAEncryption".to_string(),
        MD_5_WITH_RSA_ENCRYPTION => "md5WithRSAEncryption".to_string(),
        ID_RSASSA_PSS => "RSASSA-PSS".to_string(),
        ECDSA_WITH_SHA_256 => "ecdsa-with-SHA256".to_string(),
        ECDSA_WITH_SHA_384 => "ecdsa-with-SHA384".to_string(),
        ECDSA_WITH_SHA_512 => "ecdsa-with-SHA512".to_string(),
        ECDSA_WITH_SHA_224 => "ecdsa-with-SHA224".to_string(),
        ID_ED_25519 => "Ed25519".to_string(),
        ID_ED_448 => "Ed448".to_string(),
        other => other.to_string(),
    }
}

pub fn general_name_to_san(name: &GeneralName) -> Option<San> {
    match name {
        GeneralName::DnsName(s) => Some(San {
            kind: "dns".into(),
            value: s.to_string(),
        }),
        GeneralName::Rfc822Name(s) => Some(San {
            kind: "email".into(),
            value: s.to_string(),
        }),
        GeneralName::UniformResourceIdentifier(s) => Some(San {
            kind: "uri".into(),
            value: s.to_string(),
        }),
        GeneralName::IpAddress(bytes) => {
            let b = bytes.as_bytes();
            let value = match b.len() {
                4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b);
                    std::net::Ipv6Addr::from(arr).to_string()
                }
                _ => pem::hex(b),
            };
            Some(San {
                kind: "ip".into(),
                value,
            })
        }
        _ => None,
    }
}

pub fn san_to_general_name(san: &San) -> Result<GeneralName> {
    let ia5 = |v: &str| {
        Ia5String::new(v).map_err(|_| Error::new(format!("The name {} is not ASCII.", v)))
    };
    match san.kind.as_str() {
        "dns" => Ok(GeneralName::DnsName(ia5(&san.value)?)),
        "email" => Ok(GeneralName::Rfc822Name(ia5(&san.value)?)),
        "uri" => Ok(GeneralName::UniformResourceIdentifier(ia5(&san.value)?)),
        "ip" => {
            let addr: std::net::IpAddr = san
                .value
                .parse()
                .map_err(|_| Error::new(format!("The IP address {} is not valid.", san.value)))?;
            let bytes = match addr {
                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                std::net::IpAddr::V6(v) => v.octets().to_vec(),
            };
            Ok(GeneralName::IpAddress(OctetString::new(bytes)?))
        }
        other => Err(Error::new(format!(
            "The subject alternative name kind {} is not supported in X.509.",
            other
        ))),
    }
}

pub fn key_usage_names(ku: &KeyUsage) -> Vec<String> {
    let table = [
        (KeyUsages::DigitalSignature, "digitalSignature"),
        (KeyUsages::NonRepudiation, "nonRepudiation"),
        (KeyUsages::KeyEncipherment, "keyEncipherment"),
        (KeyUsages::DataEncipherment, "dataEncipherment"),
        (KeyUsages::KeyAgreement, "keyAgreement"),
        (KeyUsages::KeyCertSign, "keyCertSign"),
        (KeyUsages::CRLSign, "cRLSign"),
        (KeyUsages::EncipherOnly, "encipherOnly"),
        (KeyUsages::DecipherOnly, "decipherOnly"),
    ];
    table
        .iter()
        .filter(|(flag, _)| ku.0.contains(*flag))
        .map(|(_, name)| name.to_string())
        .collect()
}

pub fn eku_name(oid: &ObjectIdentifier) -> String {
    match *oid {
        ID_KP_SERVER_AUTH => "serverAuth".to_string(),
        ID_KP_CLIENT_AUTH => "clientAuth".to_string(),
        ID_KP_CODE_SIGNING => "codeSigning".to_string(),
        ID_KP_EMAIL_PROTECTION => "emailProtection".to_string(),
        ID_KP_TIME_STAMPING => "timeStamping".to_string(),
        ID_KP_OCSP_SIGNING => "OCSPSigning".to_string(),
        ANY_EXTENDED_KEY_USAGE => "anyExtendedKeyUsage".to_string(),
        other => other.to_string(),
    }
}

pub fn eku_oid(name: &str) -> Result<ObjectIdentifier> {
    match name {
        "serverAuth" => Ok(ID_KP_SERVER_AUTH),
        "clientAuth" => Ok(ID_KP_CLIENT_AUTH),
        "codeSigning" => Ok(ID_KP_CODE_SIGNING),
        "emailProtection" => Ok(ID_KP_EMAIL_PROTECTION),
        "timeStamping" => Ok(ID_KP_TIME_STAMPING),
        "OCSPSigning" => Ok(ID_KP_OCSP_SIGNING),
        "anyExtendedKeyUsage" => Ok(ANY_EXTENDED_KEY_USAGE),
        other => ObjectIdentifier::new(other).map_err(|_| {
            Error::new(format!(
                "The extended key usage {} is not a known name or an OID.",
                other
            ))
        }),
    }
}

pub struct Fingerprints {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

pub fn fingerprints(der: &[u8]) -> Fingerprints {
    Fingerprints {
        sha256: pem::hex(&Sha256::digest(der)),
        sha1: pem::hex(&Sha1::digest(der)),
        md5: pem::hex(&md5::compute(der).0),
    }
}

pub fn spki_der(cert: &Certificate) -> Result<Vec<u8>> {
    Ok(cert.tbs_certificate().subject_public_key_info().to_der()?)
}

pub fn public_key_of(cert: &Certificate) -> Result<PublicKey> {
    PublicKey::from_spki_der(&spki_der(cert)?)
}

pub fn verify_with_key(cert: &Certificate, issuer_key: &PublicKey) -> bool {
    let tbs = match cert.tbs_certificate().to_der() {
        Ok(t) => t,
        Err(_) => return false,
    };
    issuer_key.verify(
        cert.signature_algorithm(),
        &tbs,
        cert.signature().raw_bytes(),
    )
}

pub fn names_equal(a: &Name, b: &Name) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

pub fn is_self_signed(cert: &Certificate) -> bool {
    if !names_equal(
        cert.tbs_certificate().subject(),
        cert.tbs_certificate().issuer(),
    ) {
        return false;
    }
    match public_key_of(cert) {
        Ok(key) => verify_with_key(cert, &key),
        Err(_) => false,
    }
}

pub fn verify_signature(child_der: &[u8], issuer_der: &[u8]) -> Result<bool> {
    let child = parse(child_der)?;
    let issuer = parse(issuer_der)?;
    let key = public_key_of(&issuer)?;
    Ok(verify_with_key(&child, &key))
}

pub fn extension_sans(exts: &[Extension]) -> Vec<San> {
    for e in exts {
        if e.extn_id == SubjectAltName::OID {
            if let Ok(san) = SubjectAltName::from_der(e.extn_value.as_bytes()) {
                return san.0.iter().filter_map(general_name_to_san).collect();
            }
        }
    }
    Vec::new()
}

pub fn extension_eku(exts: &[Extension]) -> Vec<String> {
    for e in exts {
        if e.extn_id == ExtendedKeyUsage::OID {
            if let Ok(eku) = ExtendedKeyUsage::from_der(e.extn_value.as_bytes()) {
                return eku.0.iter().map(eku_name).collect();
            }
        }
    }
    Vec::new()
}

pub fn extension_key_usage(exts: &[Extension]) -> Vec<String> {
    for e in exts {
        if e.extn_id == KeyUsage::OID {
            if let Ok(ku) = KeyUsage::from_der(e.extn_value.as_bytes()) {
                return key_usage_names(&ku);
            }
        }
    }
    Vec::new()
}

pub fn extension_basic_constraints(exts: &[Extension]) -> (bool, Option<u32>) {
    for e in exts {
        if e.extn_id == BasicConstraints::OID {
            if let Ok(bc) = BasicConstraints::from_der(e.extn_value.as_bytes()) {
                return (bc.ca, bc.path_len_constraint.map(|p| p as u32));
            }
        }
    }
    (false, None)
}

pub fn extension_ski(exts: &[Extension]) -> Option<String> {
    exts.iter()
        .find(|e| e.extn_id == SubjectKeyIdentifier::OID)
        .and_then(|e| SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).ok())
        .map(|s| pem::hex(s.0.as_bytes()))
}

pub fn extension_aki(exts: &[Extension]) -> Option<String> {
    exts.iter()
        .find(|e| e.extn_id == AuthorityKeyIdentifier::OID)
        .and_then(|e| AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes()).ok())
        .and_then(|a| a.key_identifier.map(|k| pem::hex(k.as_bytes())))
}

pub fn facts(der: &[u8]) -> Result<Facts> {
    let cert = parse(der)?;
    let tbs = cert.tbs_certificate();
    let key = public_key_of(&cert)?;
    let exts: &[Extension] = tbs.extensions().map(|e| e.as_slice()).unwrap_or(&[]);
    let (is_ca, path_len) = extension_basic_constraints(exts);
    let fp = fingerprints(der);
    Ok(Facts {
        subject: name_map(tbs.subject()),
        issuer: name_map(tbs.issuer()),
        subject_dn: name_string(tbs.subject()),
        issuer_dn: name_string(tbs.issuer()),
        serial_hex: pem::hex(tbs.serial_number().as_bytes()),
        not_before: time_string(&tbs.validity().not_before),
        not_after: time_string(&tbs.validity().not_after),
        algorithm: key.algorithm_name().to_string(),
        bits: key.bits(),
        curve: key.curve(),
        signature_algorithm: signature_name(&cert.signature_algorithm().oid),
        self_signed: is_self_signed(&cert),
        is_ca,
        path_len,
        sans: extension_sans(exts),
        key_usage: extension_key_usage(exts),
        ext_key_usage: extension_eku(exts),
        fingerprint_sha256: fp.sha256,
        fingerprint_sha1: fp.sha1,
        fingerprint_md5: fp.md5,
        subject_key_id: extension_ski(exts),
        authority_key_id: extension_aki(exts),
        csr_signature_valid: None,
    })
}

pub fn kind(facts: &Facts) -> &'static str {
    if facts.is_ca && facts.self_signed {
        "ca"
    } else if facts.is_ca {
        "intermediate"
    } else {
        "certificate"
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Hop {
    pub from: usize,
    pub to: Option<usize>,
    pub status: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Chain {
    pub order: Vec<usize>,
    pub hops: Vec<Hop>,
}

pub fn build_chain(ders: &[Vec<u8>]) -> Result<Chain> {
    let certs: Vec<Certificate> = ders.iter().map(|d| parse(d)).collect::<Result<_>>()?;
    let keys: Vec<Option<PublicKey>> = certs.iter().map(|c| public_key_of(c).ok()).collect();
    let n = certs.len();
    let mut issuer_candidates: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..n {
            if i != j
                && names_equal(
                    certs[i].tbs_certificate().issuer(),
                    certs[j].tbs_certificate().subject(),
                )
            {
                issuer_candidates[i].push(j);
            }
        }
    }
    let mut issues_something = vec![false; n];
    for candidates in &issuer_candidates {
        for &j in candidates {
            issues_something[j] = true;
        }
    }
    let mut order = Vec::new();
    let mut hops = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut starts: Vec<usize> = (0..n).filter(|i| !issues_something[*i]).collect();
    if starts.is_empty() && n > 0 {
        starts.push(0);
    }
    for start in starts {
        if visited.contains(&start) {
            continue;
        }
        let mut current = start;
        loop {
            visited.insert(current);
            order.push(current);
            if is_self_signed(&certs[current]) {
                hops.push(Hop {
                    from: current,
                    to: None,
                    status: "self_signed".into(),
                });
                break;
            }
            let mut next: Option<(usize, bool)> = None;
            for &j in &issuer_candidates[current] {
                let ok = keys[j]
                    .as_ref()
                    .map(|k| verify_with_key(&certs[current], k))
                    .unwrap_or(false);
                if ok {
                    next = Some((j, true));
                    break;
                }
                if next.is_none() {
                    next = Some((j, false));
                }
            }
            match next {
                None => {
                    hops.push(Hop {
                        from: current,
                        to: None,
                        status: "missing_issuer".into(),
                    });
                    break;
                }
                Some((j, valid)) => {
                    hops.push(Hop {
                        from: current,
                        to: Some(j),
                        status: if valid {
                            "valid".into()
                        } else {
                            "invalid".into()
                        },
                    });
                    if visited.contains(&j) {
                        break;
                    }
                    current = j;
                }
            }
        }
    }
    for i in 0..n {
        if !visited.contains(&i) {
            order.push(i);
        }
    }
    Ok(Chain { order, hops })
}

#[derive(Serialize, Clone, Debug)]
pub struct Compared {
    pub field: String,
    pub same: bool,
}

pub fn compare(a_der: &[u8], b_der: &[u8]) -> Result<Vec<Compared>> {
    let a = facts(a_der)?;
    let b = facts(b_der)?;
    let same = |f: &str, s: bool| Compared {
        field: f.to_string(),
        same: s,
    };
    Ok(vec![
        same("subject", a.subject_dn == b.subject_dn),
        same("issuer", a.issuer_dn == b.issuer_dn),
        same("serial", a.serial_hex == b.serial_hex),
        same("not_before", a.not_before == b.not_before),
        same("not_after", a.not_after == b.not_after),
        same("algorithm", a.algorithm == b.algorithm),
        same("bits", a.bits == b.bits),
        same("sans", a.sans == b.sans),
        same(
            "fingerprint_sha256",
            a.fingerprint_sha256 == b.fingerprint_sha256,
        ),
    ])
}

pub fn ssh_certificate_facts(cert: &ssh_key::Certificate, raw: &[u8]) -> Result<Facts> {
    let key = PublicKey::from_ssh(cert.public_key())?;
    let ca = PublicKey::from_ssh(cert.signature_key())?;
    let fp = fingerprints(raw);
    let to_time = |secs: u64| -> String {
        match DateTime::from_unix_duration(core::time::Duration::from_secs(secs)) {
            Ok(dt) => date_string(&dt),
            Err(_) => date_string(&DateTime::INFINITY),
        }
    };
    Ok(Facts {
        subject: NameMap(vec![("CN".to_string(), cert.key_id().to_string())]),
        issuer: NameMap(Vec::new()),
        subject_dn: cert.key_id().to_string(),
        issuer_dn: String::new(),
        serial_hex: format!("{:x}", cert.serial()),
        not_before: to_time(cert.valid_after()),
        not_after: to_time(cert.valid_before()),
        algorithm: key.algorithm_name().to_string(),
        bits: key.bits(),
        curve: key.curve(),
        signature_algorithm: cert.signature().algorithm().as_str().to_string(),
        self_signed: false,
        is_ca: false,
        path_len: None,
        sans: cert
            .valid_principals()
            .iter()
            .map(|p| San {
                kind: "principal".into(),
                value: p.clone(),
            })
            .collect(),
        key_usage: Vec::new(),
        ext_key_usage: cert.extensions().keys().cloned().collect(),
        fingerprint_sha256: fp.sha256,
        fingerprint_sha1: fp.sha1,
        fingerprint_md5: fp.md5,
        subject_key_id: None,
        authority_key_id: Some(spki_sha256_hex(&ca.to_spki_der()?)),
        csr_signature_valid: Some(cert.verify_signature().is_ok()),
    })
}
