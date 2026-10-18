use crate::csr;
use crate::error::{Error, Result};
use crate::keys::{self, Jwk, Jwks, KeyFacts, PrivateKey, PublicKey};
use crate::pem;
use crate::pkcs12;
use crate::pkcs7;
use crate::x509::{self, Facts};
use pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum AnyFacts {
    Cert(Facts),
    Key(KeyFacts),
}

#[derive(Serialize, Clone, Debug)]
pub struct Component {
    pub kind: String,
    pub der_b64: String,
    pub pem: String,
    pub facts: Option<AnyFacts>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Detected {
    pub format: String,
    pub encrypted: bool,
    pub needs_password: bool,
    pub components: Vec<Component>,
}

fn locked(format: &str) -> Detected {
    Detected {
        format: format.to_string(),
        encrypted: true,
        needs_password: true,
        components: Vec::new(),
    }
}

pub fn cert_component(der: &[u8]) -> Result<Component> {
    let facts = x509::facts(der)?;
    Ok(Component {
        kind: x509::kind(&facts).to_string(),
        der_b64: pem::b64_encode(der),
        pem: pem::join("CERTIFICATE", der)?,
        facts: Some(AnyFacts::Cert(facts)),
    })
}

pub fn csr_component(der: &[u8]) -> Result<Component> {
    let facts = csr::facts(der)?;
    Ok(Component {
        kind: "csr".to_string(),
        der_b64: pem::b64_encode(der),
        pem: pem::join("CERTIFICATE REQUEST", der)?,
        facts: Some(AnyFacts::Cert(facts)),
    })
}

pub fn key_component(key: &PrivateKey) -> Result<Component> {
    let der = key.to_pkcs8_der()?;
    Ok(Component {
        kind: "key".to_string(),
        der_b64: pem::b64_encode(&der),
        pem: pem::join("PRIVATE KEY", &der)?,
        facts: Some(AnyFacts::Key(key.facts()?)),
    })
}

pub fn public_component(key: &PublicKey) -> Result<Component> {
    let der = key.to_spki_der()?;
    Ok(Component {
        kind: "public_key".to_string(),
        der_b64: pem::b64_encode(&der),
        pem: pem::join("PUBLIC KEY", &der)?,
        facts: Some(AnyFacts::Key(key.facts(false)?)),
    })
}

fn encrypted_component(label: &str, der: &[u8]) -> Result<Component> {
    Ok(Component {
        kind: "encrypted_key".to_string(),
        der_b64: pem::b64_encode(der),
        pem: pem::join(label, der)?,
        facts: None,
    })
}

fn ssh_cert_component(text: &str) -> Result<Component> {
    let cert = ssh_key::Certificate::from_openssh(text)?;
    let raw = cert.to_bytes()?;
    Ok(Component {
        kind: "ssh_certificate".to_string(),
        der_b64: pem::b64_encode(&raw),
        pem: format!("{}\n", text.trim()),
        facts: Some(AnyFacts::Cert(x509::ssh_certificate_facts(&cert, &raw)?)),
    })
}

fn encrypted_pkcs8(der: &[u8], password: &str, out: &mut Vec<Component>) -> Result<bool> {
    if password.is_empty() {
        out.push(encrypted_component("ENCRYPTED PRIVATE KEY", der)?);
        return Ok(true);
    }
    let plain = pkcs12::decrypt_private_key(der, password)?;
    out.push(key_component(&PrivateKey::from_pkcs8_der(&plain)?)?);
    Ok(false)
}

fn text_of(bytes: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(bytes).ok()?;
    if text.contains('\0') {
        return None;
    }
    Some(text.trim_start_matches('\u{feff}'))
}

fn detect_pem(text: &str, password: &str) -> Result<Detected> {
    let blocks = pem::split(text)?;
    let mut components = Vec::new();
    let mut encrypted = false;
    let mut needs_password = false;
    let mut all_openssh = !blocks.is_empty();
    for block in &blocks {
        let label = block.label.as_str();
        if label != "OPENSSH PRIVATE KEY" {
            all_openssh = false;
        }
        match label {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                components.push(cert_component(&block.der)?);
            }
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                components.push(csr_component(&block.der)?);
            }
            "PRIVATE KEY" => {
                components.push(key_component(&PrivateKey::from_pkcs8_der(&block.der)?)?);
            }
            "ENCRYPTED PRIVATE KEY" => {
                encrypted = true;
                if encrypted_pkcs8(&block.der, password, &mut components)? {
                    needs_password = true;
                }
            }
            "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                let legacy_encrypted = block
                    .headers
                    .iter()
                    .any(|(k, v)| k == "Proc-Type" && v.contains("ENCRYPTED"));
                if legacy_encrypted {
                    if !password.is_empty() {
                        return Err(Error::new(
                            "Legacy OpenSSL encrypted PEM keys are not supported; convert the key to PKCS#8 first.",
                        ));
                    }
                    encrypted = true;
                    needs_password = true;
                    components.push(encrypted_component(label, &block.der)?);
                } else if label == "RSA PRIVATE KEY" {
                    components.push(key_component(&PrivateKey::from_pkcs1_der(&block.der)?)?);
                } else {
                    components.push(key_component(&PrivateKey::from_sec1_der(&block.der)?)?);
                }
            }
            "PUBLIC KEY" => {
                components.push(public_component(&PublicKey::from_spki_der(&block.der)?)?);
            }
            "RSA PUBLIC KEY" => {
                let key = rsa::RsaPublicKey::from_pkcs1_der(&block.der)?;
                components.push(public_component(&PublicKey::Rsa(key))?);
            }
            "PKCS7" | "PKCS #7 SIGNED DATA" | "CMS" => {
                for der in pkcs7::read(&block.der)? {
                    components.push(cert_component(&der)?);
                }
            }
            "OPENSSH PRIVATE KEY" => {
                let parsed = keys::openssh_private_parse(&block.raw, password)?;
                if parsed.encrypted {
                    encrypted = true;
                }
                match parsed.key {
                    Some(key) => components.push(key_component(&key)?),
                    None => needs_password = true,
                }
            }
            _ => {}
        }
    }
    if components.is_empty() && !needs_password {
        return Err(Error::new("The PEM text holds no block this engine understands."));
    }
    Ok(Detected {
        format: if all_openssh { "openssh".to_string() } else { "pem".to_string() },
        encrypted,
        needs_password,
        components,
    })
}

fn detect_der(bytes: &[u8], password: &str) -> Result<Detected> {
    if pkcs12::is_pfx(bytes) {
        let contents = pkcs12::read(bytes, password)?;
        if contents.needs_password {
            return Ok(locked("pkcs12"));
        }
        let mut components = Vec::new();
        for der in &contents.certs {
            components.push(cert_component(der)?);
        }
        for key in &contents.keys {
            components.push(key_component(key)?);
        }
        return Ok(Detected {
            format: "pkcs12".to_string(),
            encrypted: true,
            needs_password: false,
            components,
        });
    }
    if let Ok(certs) = pkcs7::read(bytes) {
        let components = certs.iter().map(|d| cert_component(d)).collect::<Result<Vec<_>>>()?;
        return Ok(Detected {
            format: "pkcs7".to_string(),
            encrypted: false,
            needs_password: false,
            components,
        });
    }
    let plain = |format: &str, component: Component| Detected {
        format: format.to_string(),
        encrypted: false,
        needs_password: false,
        components: vec![component],
    };
    if x509::parse(bytes).is_ok() {
        return Ok(plain("der", cert_component(bytes)?));
    }
    if csr::parse(bytes).is_ok() {
        return Ok(plain("csr", csr_component(bytes)?));
    }
    if let Ok(key) = PrivateKey::from_pkcs8_der(bytes) {
        return Ok(plain("pkcs8", key_component(&key)?));
    }
    if pkcs12::is_encrypted_private_key(bytes) {
        let mut components = Vec::new();
        let needs_password = encrypted_pkcs8(bytes, password, &mut components)?;
        return Ok(Detected {
            format: "pkcs8".to_string(),
            encrypted: true,
            needs_password,
            components,
        });
    }
    if let Ok(key) = PrivateKey::from_pkcs1_der(bytes) {
        return Ok(plain("pkcs1", key_component(&key)?));
    }
    if let Ok(key) = PrivateKey::from_sec1_der(bytes) {
        return Ok(plain("pkcs1", key_component(&key)?));
    }
    if let Ok(key) = PublicKey::from_spki_der(bytes) {
        return Ok(plain("der", public_component(&key)?));
    }
    Ok(Detected {
        format: "unknown".to_string(),
        encrypted: false,
        needs_password: false,
        components: Vec::new(),
    })
}

pub fn detect(bytes: &[u8], _name: &str, password: &str) -> Result<Detected> {
    if let Some(text) = text_of(bytes) {
        let trimmed = text.trim();
        if pem::looks_like_pem(trimmed) {
            return detect_pem(trimmed, password);
        }
        if trimmed.starts_with("PuTTY-User-Key-File-") {
            let parsed = keys::ppk_parse(trimmed, password)?;
            return Ok(match parsed.key {
                Some(key) => Detected {
                    format: "ppk".to_string(),
                    encrypted: parsed.encrypted,
                    needs_password: false,
                    components: vec![key_component(&key)?],
                },
                None => locked("ppk"),
            });
        }
        let first = trimmed.split_whitespace().next().unwrap_or("");
        if first.ends_with("-cert-v01@openssh.com") {
            return Ok(Detected {
                format: "openssh".to_string(),
                encrypted: false,
                needs_password: false,
                components: vec![ssh_cert_component(trimmed)?],
            });
        }
        if first.starts_with("ssh-") || first.starts_with("ecdsa-sha2-") {
            let key = keys::openssh_public_parse(trimmed)?;
            return Ok(Detected {
                format: "openssh".to_string(),
                encrypted: false,
                needs_password: false,
                components: vec![public_component(&key)?],
            });
        }
        if trimmed.starts_with('{') {
            let parsed = keys::jwk_parse(trimmed)?;
            let component = match &parsed.private {
                Some(key) => key_component(key)?,
                None => public_component(&parsed.public)?,
            };
            return Ok(Detected {
                format: "jwk".to_string(),
                encrypted: false,
                needs_password: false,
                components: vec![component],
            });
        }
    }
    detect_der(bytes, password)
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConvertComponent {
    pub kind: String,
    pub der_b64: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConvertInput {
    pub components: Vec<ConvertComponent>,
    pub to: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub legacy: bool,
    #[serde(default)]
    pub friendly_name: String,
}

#[derive(Clone, Debug)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Converted {
    pub bytes: Bytes,
    pub mime: String,
    pub extension: String,
}

struct Gathered {
    certs: Vec<Vec<u8>>,
    key: Option<PrivateKey>,
    public: Option<PublicKey>,
    csrs: Vec<Vec<u8>>,
    others: Vec<(String, Vec<u8>)>,
}

fn gather(input: &ConvertInput) -> Result<Gathered> {
    let mut g = Gathered {
        certs: Vec::new(),
        key: None,
        public: None,
        csrs: Vec::new(),
        others: Vec::new(),
    };
    for c in &input.components {
        let der = pem::b64_decode(&c.der_b64)?;
        match c.kind.as_str() {
            "certificate" | "ca" | "intermediate" => g.certs.push(der),
            "key" => {
                if g.key.is_none() {
                    g.key = Some(PrivateKey::from_any_der(&der)?);
                }
            }
            "encrypted_key" => {
                if g.key.is_none() {
                    if input.password.is_empty() {
                        return Err(Error::new("The encrypted key needs a password."));
                    }
                    let plain = pkcs12::decrypt_private_key(&der, &input.password)?;
                    g.key = Some(PrivateKey::from_pkcs8_der(&plain)?);
                }
            }
            "public_key" => {
                if g.public.is_none() {
                    g.public = Some(PublicKey::from_spki_der(&der)?);
                }
            }
            "csr" => g.csrs.push(der),
            other => g.others.push((other.to_string(), der)),
        }
    }
    Ok(g)
}

fn ordered_certs(certs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let chain = x509::build_chain(certs)?;
    Ok(chain.order.iter().map(|i| certs[*i].clone()).collect())
}

fn need_key(g: &Gathered) -> Result<&PrivateKey> {
    g.key.as_ref().ok_or_else(|| Error::new("This conversion needs a private key component."))
}

fn public_of(g: &Gathered) -> Result<PublicKey> {
    if let Some(k) = &g.key {
        return Ok(k.public_key());
    }
    if let Some(p) = &g.public {
        return Ok(PublicKey::from_spki_der(&p.to_spki_der()?)?);
    }
    if let Some(c) = g.certs.first() {
        return x509::public_key_of(&x509::parse(c)?);
    }
    if let Some(c) = g.csrs.first() {
        return csr::public_key_of(&csr::parse(c)?);
    }
    Err(Error::new("This conversion needs a key, a public key or a certificate component."))
}

fn text(body: String, mime: &str, extension: &str) -> Converted {
    Converted {
        bytes: Bytes(body.into_bytes()),
        mime: mime.to_string(),
        extension: extension.to_string(),
    }
}

fn binary(body: Vec<u8>, mime: &str, extension: &str) -> Converted {
    Converted {
        bytes: Bytes(body),
        mime: mime.to_string(),
        extension: extension.to_string(),
    }
}

const PEM_MIME: &str = "application/x-pem-file";

pub fn convert(input: &ConvertInput) -> Result<Converted> {
    let g = gather(input)?;
    match input.to.as_str() {
        "pem" => {
            let mut out = String::new();
            for c in &input.components {
                let der = pem::b64_decode(&c.der_b64)?;
                let label = match c.kind.as_str() {
                    "certificate" | "ca" | "intermediate" => "CERTIFICATE",
                    "key" => "PRIVATE KEY",
                    "encrypted_key" => "ENCRYPTED PRIVATE KEY",
                    "public_key" => "PUBLIC KEY",
                    "csr" => "CERTIFICATE REQUEST",
                    other => return Err(Error::new(format!("The component kind {} has no PEM form.", other))),
                };
                let der = if label == "PRIVATE KEY" { PrivateKey::from_any_der(&der)?.to_pkcs8_der()? } else { der };
                out.push_str(&pem::join(label, &der)?);
            }
            Ok(text(out, PEM_MIME, "pem"))
        }
        "der" => {
            let first = input
                .components
                .first()
                .ok_or_else(|| Error::new("The DER conversion needs one component."))?;
            let der = pem::b64_decode(&first.der_b64)?;
            let der = if first.kind == "key" { PrivateKey::from_any_der(&der)?.to_pkcs8_der()? } else { der };
            Ok(binary(der, "application/octet-stream", "der"))
        }
        "pkcs8" => {
            let der = need_key(&g)?.to_pkcs8_der()?;
            Ok(text(pem::join("PRIVATE KEY", &der)?, PEM_MIME, "key"))
        }
        "pkcs8_encrypted" => {
            if input.password.is_empty() {
                return Err(Error::new("An encrypted PKCS#8 key needs a password."));
            }
            let der = need_key(&g)?.to_encrypted_pkcs8_der(&input.password)?;
            Ok(text(pem::join("ENCRYPTED PRIVATE KEY", &der)?, PEM_MIME, "key"))
        }
        "pkcs1" => {
            let (label, der) = need_key(&g)?.to_pkcs1_der()?;
            Ok(text(pem::join(label, &der)?, PEM_MIME, "key"))
        }
        "pkcs12" => {
            let certs = ordered_certs(&g.certs)?;
            let der = pkcs12::write(&certs, g.key.as_ref(), &input.password, input.legacy, &input.friendly_name)?;
            Ok(binary(der, "application/x-pkcs12", "pfx"))
        }
        "pkcs7" => {
            if g.certs.is_empty() {
                return Err(Error::new("A PKCS#7 bundle needs at least one certificate."));
            }
            let der = pkcs7::write(&ordered_certs(&g.certs)?)?;
            Ok(binary(der, "application/x-pkcs7-certificates", "p7b"))
        }
        "openssh" => {
            let body = keys::openssh_private_write(need_key(&g)?, &input.friendly_name, &input.password)?;
            Ok(text(body, "text/plain", "key"))
        }
        "openssh_public" => {
            let body = keys::openssh_public_write(&public_of(&g)?, &input.friendly_name)?;
            Ok(text(body, "text/plain", "pub"))
        }
        "ppk" => {
            let body = keys::ppk_write(need_key(&g)?, &input.friendly_name, &input.password)?;
            Ok(text(body, "text/plain", "ppk"))
        }
        "jwk" => {
            let jwk: Jwk = match &g.key {
                Some(k) => k.to_jwk()?,
                None => public_of(&g)?.to_jwk()?,
            };
            Ok(text(keys::json_stringify(&jwk)?, "application/json", "json"))
        }
        "jwks_public" => {
            let set = Jwks { keys: vec![public_of(&g)?.to_jwk()?] };
            Ok(text(keys::json_stringify(&set)?, "application/json", "json"))
        }
        "fullchain" => {
            if g.certs.is_empty() {
                return Err(Error::new("A full chain needs at least one certificate."));
            }
            let mut out = String::new();
            for der in ordered_certs(&g.certs)? {
                out.push_str(&pem::join("CERTIFICATE", &der)?);
            }
            Ok(text(out, PEM_MIME, "pem"))
        }
        "combined" => {
            let mut out = String::new();
            out.push_str(&pem::join("PRIVATE KEY", &need_key(&g)?.to_pkcs8_der()?)?);
            for der in ordered_certs(&g.certs)? {
                out.push_str(&pem::join("CERTIFICATE", &der)?);
            }
            Ok(text(out, PEM_MIME, "pem"))
        }
        other => Err(Error::new(format!("The target format {} is not one this engine writes.", other))),
    }
}

pub fn public_key_hash(der: &[u8], kind: &str) -> Result<String> {
    let spki = match kind {
        "certificate" | "ca" | "intermediate" => x509::spki_der(&x509::parse(der)?)?,
        "key" => PrivateKey::from_any_der(der)?.public_key().to_spki_der()?,
        "csr" => csr::public_key_of(&csr::parse(der)?)?.to_spki_der()?,
        "public_key" => PublicKey::from_spki_der(der)?.to_spki_der()?,
        other => return Err(Error::new(format!("The kind {} has no public key to hash.", other))),
    };
    Ok(keys::spki_sha256_hex(&spki))
}
