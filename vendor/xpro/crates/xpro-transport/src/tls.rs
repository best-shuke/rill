use crate::Io;
use boring::{
    ssl::{SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion},
    x509::X509,
};
use std::{io, path::Path};
pub fn exporter(ssl: &SslRef) -> io::Result<[u8; 32]> {
    let mut out = [0; 32];
    ssl.export_keying_material(&mut out, "EXPORTER-Channel-Binding", Some(&[]))
        .map_err(io::Error::other)?;
    Ok(out)
}
pub fn connector(ca: Option<&Path>, alpn: &[u8]) -> io::Result<SslConnector> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(io::Error::other)?;
    b.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(io::Error::other)?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(io::Error::other)?;
    b.set_verify(SslVerifyMode::PEER);
    let mut store = boring::x509::store::X509StoreBuilder::new().map_err(io::Error::other)?;
    // A supplied private CA replaces the public and OS root sets.
    if let Some(path) = ca {
        let certificates = X509::stack_from_pem(&std::fs::read(path)?).map_err(io::Error::other)?;
        if certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty CA bundle",
            ));
        }
        for cert in certificates {
            store.add_cert(cert).map_err(io::Error::other)?;
        }
    } else {
        for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            store
                .add_cert(X509::from_der(cert.as_ref()).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
    }
    b.set_cert_store(store.build());
    b.set_alpn_protos(alpn).map_err(io::Error::other)?;
    Ok(b.build())
}
pub async fn connect<S: Io>(
    connector: &SslConnector,
    name: &str,
    io: S,
) -> io::Result<tokio_boring::SslStream<S>> {
    let config = connector.configure().map_err(io::Error::other)?;
    tokio_boring::connect(config, name, io)
        .await
        .map_err(|error| {
            if let Some(code) = error
                .ssl()
                .filter(|ssl| ssl.peer_certificate().is_some())
                .and_then(|ssl| ssl.verify_result().err())
            {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "TLS certificate verification failed (code {})",
                        code.as_raw()
                    ),
                )
            } else if let Some(e) = error.as_io_error() {
                io::Error::new(e.kind(), "TLS transport failed")
            } else {
                io::Error::new(io::ErrorKind::PermissionDenied, "TLS handshake failed")
            }
        })
}
