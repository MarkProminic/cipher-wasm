use crate::csr;
use crate::error::{Error, Result};
use crate::keys::{random_bytes, rng, PrivateKey, PublicKey, Scheme};
use crate::x509::{self, NameMap, San};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
use der::flagset::FlagSet;
use der::{DateTime, Decode, Encode};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use signature::{Keypair, Signer};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
    SubjectPublicKeyInfoRef,
};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::TbsCertificate;

#[derive(Clone, Copy)]
pub struct Term {
    pub days: u32,
    pub is_ca: bool,
    pub path_len: Option<u8>,
}

pub struct Issue<'a> {
    pub signer: &'a PrivateKey,
    pub scheme: Scheme,
    pub issuer_name: Name,
    pub subject: Name,
    pub subject_key: &'a PublicKey,
    pub term: Term,
    pub sans: Vec<San>,
    pub eku: Vec<String>,
    pub extra: Vec<Extension>,
}

struct Profile {
    issuer: Name,
    subject: Name,
    is_ca: bool,
    path_len: Option<u8>,
    key_usage: FlagSet<KeyUsages>,
    sans: Vec<GeneralName>,
    eku: Vec<ObjectIdentifier>,
    extra: Vec<Extension>,
}

fn key_identifier(spki: SubjectPublicKeyInfoRef<'_>) -> Vec<u8> {
    Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec()
}

struct Ed448Signer<'a>(&'a ed448_goldilocks::SigningKey);

impl Keypair for Ed448Signer<'_> {
    type VerifyingKey = ed448_goldilocks::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl DynSignatureAlgorithmIdentifier for Ed448Signer<'_> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        self.0.signature_algorithm_identifier()
    }
}

impl Signer<ed448_goldilocks::Signature> for Ed448Signer<'_> {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<ed448_goldilocks::Signature> {
        self.0.try_sign(msg)
    }
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut exts: Vec<Extension> = Vec::new();
        let ski = SubjectKeyIdentifier(OctetString::new(key_identifier(spk))?);
        exts.push((&ski).to_extension(subject, &exts)?);
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(key_identifier(issuer_spk))?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        exts.push((&aki).to_extension(subject, &exts)?);
        let bc = BasicConstraints {
            ca: self.is_ca,
            path_len_constraint: if self.is_ca { self.path_len } else { None },
        };
        exts.push((&bc).to_extension(subject, &exts)?);
        let ku = KeyUsage(self.key_usage);
        exts.push((&ku).to_extension(subject, &exts)?);
        if !self.sans.is_empty() {
            let san = SubjectAltName(self.sans.clone());
            exts.push((&san).to_extension(subject, &exts)?);
        }
        if !self.eku.is_empty() {
            let eku = ExtendedKeyUsage(self.eku.clone());
            exts.push((&eku).to_extension(subject, &exts)?);
        }
        let reserved = [
            SubjectKeyIdentifier::OID,
            AuthorityKeyIdentifier::OID,
            BasicConstraints::OID,
            KeyUsage::OID,
            SubjectAltName::OID,
            ExtendedKeyUsage::OID,
        ];
        for e in &self.extra {
            if !reserved.contains(&e.extn_id) {
                exts.push(e.clone());
            }
        }
        Ok(exts)
    }
}

fn time_from_secs(secs: u64) -> Result<Time> {
    let dt = DateTime::from_unix_duration(core::time::Duration::from_secs(secs)).map_err(|_| {
        Error::new("The validity period falls outside the dates a certificate can hold.")
    })?;
    Ok(Time::from(dt))
}

fn now_secs() -> u64 {
    let ms = js_sys::Date::now();
    if ms.is_finite() && ms > 0.0 {
        (ms / 1000.0) as u64
    } else {
        0
    }
}

pub fn issue(p: Issue<'_>) -> Result<Vec<u8>> {
    if p.term.days == 0 {
        return Err(Error::new("The validity in days must be at least one."));
    }
    let mut serial = random_bytes(20)?;
    serial[0] &= 0x7f;
    if serial.iter().all(|b| *b == 0) {
        serial[19] = 1;
    }
    let serial_number = SerialNumber::new(&serial)?;
    let start = now_secs();
    let end = start
        .checked_add(u64::from(p.term.days) * 86_400)
        .ok_or_else(|| Error::new("The validity period is too long."))?;
    let validity = Validity::new(time_from_secs(start)?, time_from_secs(end)?);
    let subject_spki = SubjectPublicKeyInfoOwned::from_der(&p.subject_key.to_spki_der()?)?;
    let key_usage = if p.term.is_ca {
        KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature
    } else {
        match p.subject_key {
            PublicKey::Rsa(_) => KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment,
            _ => KeyUsages::DigitalSignature.into(),
        }
    };
    let sans = p
        .sans
        .iter()
        .map(x509::san_to_general_name)
        .collect::<Result<Vec<_>>>()?;
    let eku = p
        .eku
        .iter()
        .map(|n| x509::eku_oid(n))
        .collect::<Result<Vec<_>>>()?;
    let profile = Profile {
        issuer: p.issuer_name,
        subject: p.subject,
        is_ca: p.term.is_ca,
        path_len: p.term.path_len,
        key_usage,
        sans,
        eku,
        extra: p.extra,
    };
    let builder = CertificateBuilder::new(profile, serial_number, validity, subject_spki)?;
    let cert = match p.signer {
        PrivateKey::Rsa(k) => match p.scheme {
            Scheme::Pkcs1 => builder.build::<_, rsa::pkcs1v15::Signature>(
                &rsa::pkcs1v15::SigningKey::<Sha256>::new(k.clone()),
            )?,
            Scheme::Pss => builder.build_with_rng::<_, rsa::pss::Signature, _>(
                &rsa::pss::SigningKey::<Sha256>::new(k.clone()),
                &mut rng(),
            )?,
        },
        PrivateKey::P256(k) => builder
            .build::<_, ecdsa::der::Signature<p256::NistP256>>(&p256::ecdsa::SigningKey::from(k))?,
        PrivateKey::P384(k) => builder
            .build::<_, ecdsa::der::Signature<p384::NistP384>>(&p384::ecdsa::SigningKey::from(k))?,
        PrivateKey::P521(k) => builder
            .build::<_, ecdsa::der::Signature<p521::NistP521>>(&p521::ecdsa::SigningKey::from(k))?,
        PrivateKey::K256(k) => builder.build::<_, ecdsa::der::Signature<k256::Secp256k1>>(
            &k256::ecdsa::SigningKey::from(k),
        )?,
        PrivateKey::Ed25519(k) => builder.build::<_, ed25519_dalek::Signature>(k)?,
        PrivateKey::Ed448(k) => {
            builder.build::<_, ed448_goldilocks::Signature>(&Ed448Signer(k.as_ref()))?
        }
    };
    Ok(cert.to_der()?)
}

pub fn self_sign(
    key_der: &[u8],
    scheme: Scheme,
    subject: &NameMap,
    sans: Vec<San>,
    eku: Vec<String>,
    term: Term,
) -> Result<Vec<u8>> {
    let key = PrivateKey::from_pkcs8_der(key_der)?;
    let public = key.public_key();
    let name = x509::name_from_map(subject)?;
    issue(Issue {
        signer: &key,
        scheme,
        issuer_name: name.clone(),
        subject: name,
        subject_key: &public,
        term,
        sans,
        eku,
        extra: Vec::new(),
    })
}

pub fn sign_csr(
    csr_der: &[u8],
    ca_cert_der: &[u8],
    ca_key_der: &[u8],
    scheme: Scheme,
    term: Term,
    copy_extensions: bool,
) -> Result<Vec<u8>> {
    let req = csr::parse(csr_der)?;
    if !csr::verify(&req) {
        return Err(Error::new(
            "The certificate request's signature is not valid.",
        ));
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
        (
            x509::extension_sans(&exts),
            x509::extension_eku(&exts),
            exts,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    issue(Issue {
        signer: &ca_key,
        scheme,
        issuer_name: ca_cert.tbs_certificate().subject().clone(),
        subject: req.info.subject.clone(),
        subject_key: &subject_key,
        term,
        sans,
        eku,
        extra,
    })
}
