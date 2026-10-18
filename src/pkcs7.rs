use crate::error::{Error, Result};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::{Decode, Encode};
use x509_cert::{Certificate, PkiPath};

pub fn read(der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let info = ContentInfo::from_der(der).map_err(|_| Error::new("The data is not a PKCS#7 document."))?;
    if info.content_type != ID_SIGNED_DATA {
        return Err(Error::new("The PKCS#7 document is not signed-data and holds no certificates."));
    }
    let signed = SignedData::from_der(&info.content.to_der()?)?;
    let mut out = Vec::new();
    if let Some(set) = signed.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                out.push(cert.to_der()?);
            }
        }
    }
    Ok(out)
}

pub fn write(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let path: PkiPath = certs
        .iter()
        .map(|d| Certificate::from_der(d))
        .collect::<der::Result<_>>()?;
    Ok(ContentInfo::try_from(path)?.to_der()?)
}
