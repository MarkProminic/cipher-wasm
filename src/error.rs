use core::fmt;

#[derive(Debug, Clone)]
pub struct Error(pub String);

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Error::new("The data is not valid ASN.1 DER.")
    }
}

impl From<base64ct::Error> for Error {
    fn from(_: base64ct::Error) -> Self {
        Error::new("The data is not valid base64.")
    }
}

impl From<pkcs8::Error> for Error {
    fn from(_: pkcs8::Error) -> Self {
        Error::new("The private key could not be read.")
    }
}

impl From<spki::Error> for Error {
    fn from(_: spki::Error) -> Self {
        Error::new("The public key could not be read.")
    }
}

impl From<pkcs5::Error> for Error {
    fn from(_: pkcs5::Error) -> Self {
        Error::new("The password-based encryption failed.")
    }
}

impl From<pkcs1::Error> for Error {
    fn from(_: pkcs1::Error) -> Self {
        Error::new("The RSA key could not be read.")
    }
}

impl From<rsa::Error> for Error {
    fn from(_: rsa::Error) -> Self {
        Error::new("The RSA operation failed.")
    }
}

impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Self {
        Error::new("The signature operation failed.")
    }
}

impl From<p256::elliptic_curve::Error> for Error {
    fn from(_: p256::elliptic_curve::Error) -> Self {
        Error::new("The elliptic curve key is not valid.")
    }
}

impl From<ssh_key::Error> for Error {
    fn from(_: ssh_key::Error) -> Self {
        Error::new("The SSH key could not be read.")
    }
}

impl From<ssh_key::encoding::Error> for Error {
    fn from(_: ssh_key::encoding::Error) -> Self {
        Error::new("The SSH wire encoding is not valid.")
    }
}

impl From<serde_wasm_bindgen::Error> for Error {
    fn from(e: serde_wasm_bindgen::Error) -> Self {
        Error::new(format!("The input shape is not valid: {}.", e))
    }
}

impl From<argon2::Error> for Error {
    fn from(_: argon2::Error) -> Self {
        Error::new("The Argon2 key derivation failed.")
    }
}

impl From<x509_cert::builder::Error> for Error {
    fn from(e: x509_cert::builder::Error) -> Self {
        Error::new(format!("The certificate could not be built: {}.", e))
    }
}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Error::new("The random number source failed.")
    }
}

impl From<Error> for wasm_bindgen::JsError {
    fn from(e: Error) -> Self {
        wasm_bindgen::JsError::new(&e.0)
    }
}
