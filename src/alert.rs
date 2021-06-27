use crate::parse_buffer::ParseBuffer;
use crate::TlsError;

#[derive(Debug)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

impl AlertLevel {
    pub fn of(num: u8) -> Option<Self> {
        match num {
            1 => Some(AlertLevel::Warning),
            2 => Some(AlertLevel::Fatal),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl AlertDescription {
    pub fn of(num: u8) -> Option<Self> {
        match num {
            0 => Some(AlertDescription::CloseNotify),
            10 => Some(AlertDescription::UnexpectedMessage),
            20 => Some(AlertDescription::BadRecordMac),
            22 => Some(AlertDescription::RecordOverflow),
            40 => Some(AlertDescription::HandshakeFailure),
            42 => Some(AlertDescription::BadCertificate),
            43 => Some(AlertDescription::UnsupportedCertificate),
            44 => Some(AlertDescription::CertificateRevoked),
            45 => Some(AlertDescription::CertificateExpired),
            46 => Some(AlertDescription::CertificateUnknown),
            47 => Some(AlertDescription::IllegalParameter),
            48 => Some(AlertDescription::UnknownCa),
            49 => Some(AlertDescription::AccessDenied),
            50 => Some(AlertDescription::DecodeError),
            51 => Some(AlertDescription::DecryptError),
            70 => Some(AlertDescription::ProtocolVersion),
            71 => Some(AlertDescription::InsufficientSecurity),
            80 => Some(AlertDescription::InternalError),
            86 => Some(AlertDescription::InappropriateFallback),
            90 => Some(AlertDescription::UserCanceled),
            109 => Some(AlertDescription::MissingExtension),
            110 => Some(AlertDescription::UnsupportedExtension),
            112 => Some(AlertDescription::UnrecognizedName),
            113 => Some(AlertDescription::BadCertificateStatusResponse),
            115 => Some(AlertDescription::UnknownPskIdentity),
            116 => Some(AlertDescription::CertificateRequired),
            120 => Some(AlertDescription::NoApplicationProtocol),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

impl Alert {
    pub fn parse(buf: &mut ParseBuffer<'_>) -> Result<Alert, TlsError> {
        let level = buf.read_u8()?;
        let desc = buf.read_u8()?;

        Ok(Self {
            level: AlertLevel::of(level).ok_or(TlsError::DecodeError)?,
            description: AlertDescription::of(desc).ok_or(TlsError::DecodeError)?,
        })
    }
}
