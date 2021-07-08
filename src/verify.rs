use crate::config::{Certificate, TlsCipherSuite, TlsConfig};
use crate::handshake::certificate::{Certificate as ServerCertificate, CertificateEntry};
use crate::TlsError;
use core::convert::TryFrom;
use webpki::DnsNameRef;

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
];

pub(crate) fn verify_certificate<'a, CipherSuite>(
    config: &TlsConfig<'a, CipherSuite>,
    certificate: ServerCertificate,
    now: u64,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    let mut verified = false;
    let mut host_verified = false;
    if config.verify_cert {
        if let Some(Certificate::X509(ca)) = config.ca {
            info!("Loaded CA");
            let trust = webpki::TrustAnchor::try_from_cert_der(ca).map_err(|e| {
                info!("ERROR Loading CA: {:?}", e);
                TlsError::DecodeError
            })?;
            info!("Loaded trust");
            let anchors = &[trust];
            let anchors = webpki::TlsServerTrustAnchors(anchors);
            let time = webpki::Time::from_seconds_since_unix_epoch(now);

            info!("We got {} certificate entries", certificate.entries.len());

            if !certificate.entries.is_empty() {
                // TODO: Support intermediates...
                if let CertificateEntry::X509(certificate) = certificate.entries[0] {
                    info!("Loading certificate with len {}", certificate.len());
                    let cert = webpki::EndEntityCert::try_from(certificate).map_err(|e| {
                        info!("Error loading cert: {:?}", e);
                        TlsError::DecodeError
                    })?;
                    info!("Certificate is loaded!");
                    match cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time) {
                        Ok(_) => verified = true,
                        Err(e) => {
                            warn!("Error verifying certificate: {:?}", e);
                        }
                    }

                    if config.verify_host && config.server_name.is_some() {
                        match cert.verify_is_valid_for_dns_name(
                            DnsNameRef::try_from_ascii_str(config.server_name.unwrap()).unwrap(),
                        ) {
                            Ok(_) => host_verified = true,
                            Err(e) => {
                                warn!("Error verifying host: {:?}", e);
                            }
                        }
                    }
                }
            }
        }
    }
    if !verified && config.verify_cert {
        return Err(TlsError::InvalidCertificate);
    }

    if !host_verified && config.verify_host {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}
