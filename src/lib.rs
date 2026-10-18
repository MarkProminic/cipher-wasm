mod csr;
mod detect;
mod error;
mod issue;
mod keys;
mod pem;
mod pkcs12;
mod pkcs7;
mod x509;

use error::Result;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use x509::{NameMap, San};

fn to_js<T: Serialize>(value: &T) -> Result<JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_maps_as_objects(true)
        .serialize_missing_as_null(true);
    Ok(value.serialize(&serializer)?)
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue) -> Result<T> {
    Ok(serde_wasm_bindgen::from_value(value)?)
}

#[wasm_bindgen]
pub fn detect(bytes: &[u8], name: &str, password: &str) -> core::result::Result<JsValue, JsError> {
    Ok(to_js(&detect::detect(bytes, name, password)?)?)
}

#[wasm_bindgen]
pub fn convert(input: JsValue) -> core::result::Result<JsValue, JsError> {
    let input: detect::ConvertInput = from_js(input)?;
    Ok(to_js(&detect::convert(&input)?)?)
}

#[wasm_bindgen]
pub fn public_key_hash(der_b64: &str, kind: &str) -> core::result::Result<String, JsError> {
    let der = pem::b64_decode(der_b64)?;
    Ok(detect::public_key_hash(&der, kind)?)
}

#[wasm_bindgen]
pub fn verify_signature(
    child_der_b64: &str,
    issuer_der_b64: &str,
) -> core::result::Result<bool, JsError> {
    let child = pem::b64_decode(child_der_b64)?;
    let issuer = pem::b64_decode(issuer_der_b64)?;
    Ok(x509::verify_signature(&child, &issuer)?)
}

#[wasm_bindgen]
pub fn build_chain(certs: JsValue) -> core::result::Result<JsValue, JsError> {
    let encoded: Vec<String> = from_js(certs)?;
    let ders = encoded
        .iter()
        .map(|c| pem::b64_decode(c))
        .collect::<Result<Vec<_>>>()?;
    Ok(to_js(&x509::build_chain(&ders)?)?)
}

#[wasm_bindgen]
pub fn compare(a_der_b64: &str, b_der_b64: &str) -> core::result::Result<JsValue, JsError> {
    let a = pem::b64_decode(a_der_b64)?;
    let b = pem::b64_decode(b_der_b64)?;
    Ok(to_js(&x509::compare(&a, &b)?)?)
}

#[derive(Serialize)]
struct GeneratedKey {
    der_b64: String,
    facts: keys::KeyFacts,
}

#[wasm_bindgen]
pub fn generate_key(alg: &str) -> core::result::Result<JsValue, JsError> {
    let key = keys::PrivateKey::generate(alg)?;
    let out = GeneratedKey {
        der_b64: pem::b64_encode(&key.to_pkcs8_der()?),
        facts: key.facts()?,
    };
    Ok(to_js(&out)?)
}

#[derive(Deserialize)]
struct CsrInput {
    key_der_b64: String,
    subject: NameMap,
    #[serde(default)]
    sans: Vec<San>,
    #[serde(default)]
    ext_key_usage: Vec<String>,
}

#[derive(Serialize)]
struct CsrOutput {
    der_b64: String,
    pem: String,
}

#[wasm_bindgen]
pub fn make_csr(input: JsValue) -> core::result::Result<JsValue, JsError> {
    let input: CsrInput = from_js(input)?;
    let key = keys::PrivateKey::from_pkcs8_der(&pem::b64_decode(&input.key_der_b64)?)?;
    let der = csr::build(&key, &input.subject, &input.sans, &input.ext_key_usage)?;
    let out = CsrOutput {
        der_b64: pem::b64_encode(&der),
        pem: pem::join("CERTIFICATE REQUEST", &der)?,
    };
    Ok(to_js(&out)?)
}

#[derive(Deserialize)]
struct SelfSignInput {
    key_der_b64: String,
    subject: NameMap,
    #[serde(default)]
    sans: Vec<San>,
    #[serde(default)]
    ext_key_usage: Vec<String>,
    days: u32,
    #[serde(default)]
    is_ca: bool,
    #[serde(default)]
    path_len: Option<u8>,
}

#[derive(Serialize)]
struct IssuedOutput {
    der_b64: String,
    pem: String,
    facts: x509::Facts,
}

fn issued(der: Vec<u8>) -> Result<JsValue> {
    let out = IssuedOutput {
        der_b64: pem::b64_encode(&der),
        pem: pem::join("CERTIFICATE", &der)?,
        facts: x509::facts(&der)?,
    };
    to_js(&out)
}

#[wasm_bindgen]
pub fn self_sign(input: JsValue) -> core::result::Result<JsValue, JsError> {
    let input: SelfSignInput = from_js(input)?;
    let der = issue::self_sign(
        &pem::b64_decode(&input.key_der_b64)?,
        &input.subject,
        input.sans,
        input.ext_key_usage,
        input.days,
        input.is_ca,
        input.path_len,
    )?;
    Ok(issued(der)?)
}

#[derive(Deserialize)]
struct SignCsrInput {
    csr_der_b64: String,
    ca_cert_der_b64: String,
    ca_key_der_b64: String,
    days: u32,
    #[serde(default)]
    is_ca: bool,
    #[serde(default)]
    path_len: Option<u8>,
    #[serde(default)]
    copy_extensions: bool,
}

#[wasm_bindgen]
pub fn sign_csr(input: JsValue) -> core::result::Result<JsValue, JsError> {
    let input: SignCsrInput = from_js(input)?;
    let der = issue::sign_csr(
        &pem::b64_decode(&input.csr_der_b64)?,
        &pem::b64_decode(&input.ca_cert_der_b64)?,
        &pem::b64_decode(&input.ca_key_der_b64)?,
        input.days,
        input.is_ca,
        input.path_len,
        input.copy_extensions,
    )?;
    Ok(issued(der)?)
}
