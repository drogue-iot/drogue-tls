use crate::buffer::CryptoBuffer;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::{consts::*, Vec};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate<'a> {
    request_context: &'a [u8],
    pub(crate) entries: Vec<CertificateEntry<'a>, U16>,
}

impl<'a> Certificate<'a> {
    pub fn with_context(request_context: &'a [u8]) -> Self {
        Self {
            request_context,
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: CertificateEntry<'a>) -> Result<(), TlsError> {
        self.entries
            .push(entry)
            .map_err(|_| TlsError::InsufficientSpace)
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let request_context_len = buf.read_u8().map_err(|_| TlsError::InvalidCertificate)?;
        let request_context = buf
            .slice(request_context_len as usize)
            .map_err(|_| TlsError::InvalidCertificate)?;
        let entries_len = buf.read_u24().map_err(|_| TlsError::InvalidCertificate)?;
        let mut entries = buf
            .slice(entries_len as usize)
            .map_err(|_| TlsError::InvalidCertificate)?;

        let entries = CertificateEntry::parse_vector(&mut entries)?;

        Ok(Self {
            request_context: request_context.as_slice(),
            entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(self.request_context.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(self.request_context)
            .map_err(|_| TlsError::EncodeError)?;

        buf.push_u24(self.entries.len() as u32)?;
        for entry in self.entries.iter() {
            entry.encode(buf)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CertificateEntry<'a> {
    X509(&'a [u8]),
    RawPublicKey(&'a [u8]),
}

impl<'a> CertificateEntry<'a> {
    pub fn parse_vector(
        buf: &mut ParseBuffer<'a>,
    ) -> Result<Vec<CertificateEntry<'a>, U16>, TlsError> {
        let mut entries = Vec::new();
        loop {
            let entry_len = buf.read_u24().map_err(|_| TlsError::InvalidCertificate)?;
            // info!("cert len: {}", entry_len);
            let cert = buf
                .slice(entry_len as usize)
                .map_err(|_| TlsError::InvalidCertificate)?;

            //let cert: Result<Vec<u8, _>, ()> = cert.into();
            // let cert: Result<Vec<u8, _>, ()> = Ok(Vec::new());

            entries
                .push(CertificateEntry::X509(cert.as_slice()))
                .map_err(|_| TlsError::DecodeError)?;

            let _extensions_len = buf
                .read_u16()
                .map_err(|_| TlsError::InvalidExtensionsLength)?;

            if buf.is_empty() {
                break;
            }
        }
        Ok(entries)
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        /*
        match self {
            CertificateEntry::RawPublicKey(key) => {
                let entry_len = (key.len() as u32).to_be_bytes();
            }
            CertificateEntry::X509(cert) => {
                let entry_len = (cert.len() as u32).to_be_bytes();
            }
        }
        */
        Ok(())
    }
}

impl<'a> From<crate::config::Certificate<'a>> for CertificateEntry<'a> {
    fn from(cert: crate::config::Certificate<'a>) -> Self {
        match cert {
            crate::Certificate::X509(data) => CertificateEntry::X509(data),
            crate::Certificate::RawPublicKey(data) => CertificateEntry::RawPublicKey(data),
        }
    }
}
