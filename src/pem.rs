use crate::error::{Error, Result};
use base64ct::{Base64, Base64UrlUnpadded, Encoding, LineEnding};

pub struct Block {
    pub label: String,
    pub headers: Vec<(String, String)>,
    pub der: Vec<u8>,
    pub raw: String,
}

pub fn looks_like_pem(text: &str) -> bool {
    text.contains("-----BEGIN ")
}

pub fn split(text: &str) -> Result<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut label: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = String::new();
    let mut raw_block = String::new();
    let mut in_headers = false;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let name = rest.trim_end_matches('-').trim();
            label = Some(name.to_string());
            headers.clear();
            body.clear();
            raw_block.clear();
            raw_block.push_str(line);
            raw_block.push('\n');
            in_headers = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            let name = rest.trim_end_matches('-').trim();
            if let Some(current) = label.take() {
                if current != name {
                    return Err(Error::new("A PEM block's BEGIN and END labels do not match."));
                }
                raw_block.push_str(line);
                raw_block.push('\n');
                let der = b64_decode(&body)?;
                blocks.push(Block {
                    label: current,
                    headers: core::mem::take(&mut headers),
                    der,
                    raw: core::mem::take(&mut raw_block),
                });
            }
            continue;
        }
        if label.is_none() {
            continue;
        }
        raw_block.push_str(line);
        raw_block.push('\n');
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                if !k.contains(|c: char| c == '=' || c == '/' || c == '+') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                    continue;
                }
            }
            in_headers = false;
        }
        body.push_str(line);
    }
    if label.is_some() {
        return Err(Error::new("A PEM block is missing its END line."));
    }
    Ok(blocks)
}

pub fn join(label: &str, der: &[u8]) -> Result<String> {
    pem_rfc7468::encode_string(label, LineEnding::LF, der)
        .map_err(|_| Error::new("The PEM document could not be written."))
}

pub fn b64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(Base64::decode_vec(&compact)?)
}

pub fn b64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

pub fn b64url_decode(text: &str) -> Result<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    Ok(Base64UrlUnpadded::decode_vec(&compact)?)
}

pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn unhex(text: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    if compact.len() % 2 != 0 {
        return Err(Error::new("The hex string has an odd length."));
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for i in (0..compact.len()).step_by(2) {
        let byte = u8::from_str_radix(&compact[i..i + 2], 16)
            .map_err(|_| Error::new("The hex string holds a character that is not hex."))?;
        out.push(byte);
    }
    Ok(out)
}
