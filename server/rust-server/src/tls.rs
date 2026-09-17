use std::path::Path;

use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertifiedKey, generate_simple_self_signed};

/// Ensures self-signed cert and key PEM files exist at the given paths.
/// If either file is missing, generates a new self-signed certificate
/// with SANs for `localhost` and `127.0.0.1`.
pub fn ensure_self_signed_certs(cert_path: &str, key_path: &str) -> anyhow::Result<()> {
    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        tracing::info!("TLS certs already exist at {cert_path} and {key_path}");
        return Ok(());
    }

    tracing::info!("Generating self-signed TLS certificate...");

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

    // Ensure parent directory exists
    if let Some(parent) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;

    tracing::info!("Self-signed TLS cert written to {cert_path} and {key_path}");
    Ok(())
}

/// Loads a `RustlsConfig` from PEM cert and key files.
pub async fn load_rustls_config(cert_path: &str, key_path: &str) -> anyhow::Result<RustlsConfig> {
    let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    Ok(config)
}
