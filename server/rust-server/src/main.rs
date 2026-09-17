mod client_msg;
mod config;
mod data;
mod db;
mod error;
mod http;
mod models;
mod module_builder;
mod tls;
mod ws;

use anyhow::{Context, bail};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// If set, send this file as the module blob instead of building from DB.
    pub raw_module: Option<Vec<u8>>,
    /// Maps client IP → auth_token from the most recent WebSocket connection.
    pub ip_tokens: Arc<RwLock<HashMap<IpAddr, String>>>,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::new("debug"))
        .init();

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| config::DEFAULT_DATABASE_URL.to_string());

    let db = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to PostgreSQL");

    run_migrations_or_validate_schema(&db)
        .await
        .expect("database schema is not ready");

    // --raw-module <path>: bypass DB, send this encrypted file directly
    // --raw-decrypted-module <path>: read decrypted flatbuffer, compress+encrypt, then send
    let raw_module = {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--raw-module") {
            let path = args.get(i + 1).expect("--raw-module requires a path");
            let data = std::fs::read(path)
                .unwrap_or_else(|e| panic!("failed to read raw module {path}: {e}"));
            tracing::info!(
                "Raw module override (encrypted): {} ({} bytes)",
                path,
                data.len()
            );
            Some(data)
        } else if let Some(i) = args.iter().position(|a| a == "--raw-decrypted-module") {
            let path = args
                .get(i + 1)
                .expect("--raw-decrypted-module requires a path");
            let data = std::fs::read(path)
                .unwrap_or_else(|e| panic!("failed to read decrypted module {path}: {e}"));
            tracing::info!(
                "Raw module override (decrypted flatbuffer): {} ({} bytes), compressing+encrypting...",
                path,
                data.len()
            );
            let encrypted = nl_parser::pipeline::save_module(&data)
                .expect("failed to compress+encrypt decrypted module");
            tracing::info!("Encrypted module: {} bytes", encrypted.len());
            Some(encrypted)
        } else if let Some(i) = args.iter().position(|a| a == "--reencrypt-module") {
            // Read encrypted module.bin, decrypt+decompress, then re-compress+encrypt
            // Tests that the compress/encrypt pipeline produces a working result
            let path = args.get(i + 1).expect("--reencrypt-module requires a path");
            let data =
                std::fs::read(path).unwrap_or_else(|e| panic!("failed to read module {path}: {e}"));
            tracing::info!(
                "Re-encrypt module: {} ({} bytes), decrypting+decompressing...",
                path,
                data.len()
            );
            let decompressed = nl_parser::pipeline::load_module(&data)
                .expect("failed to decrypt+decompress module");
            tracing::info!(
                "Decompressed flatbuffer: {} bytes, re-compressing+encrypting...",
                decompressed.len()
            );
            let encrypted = nl_parser::pipeline::save_module(&decompressed)
                .expect("failed to compress+encrypt module");
            tracing::info!("Re-encrypted module: {} bytes", encrypted.len());
            Some(encrypted)
        } else {
            None
        }
    };

    let state = AppState {
        db,
        raw_module,
        ip_tokens: Arc::new(RwLock::new(HashMap::new())),
    };

    let http_addr = SocketAddr::from(([0, 0, 0, 0], config::HTTP_PORT));
    let ws_addr = SocketAddr::from(([0, 0, 0, 0], config::WS_PORT));

    let ws_tls = std::env::var("WS_TLS").unwrap_or_else(|_| "true".to_string());
    let ws_tls_enabled = ws_tls != "false";

    let cert_path = std::env::var("TLS_CERT").unwrap_or_else(|_| config::TLS_CERT_PATH.to_string());
    let key_path = std::env::var("TLS_KEY").unwrap_or_else(|_| config::TLS_KEY_PATH.to_string());

    let http_listener = TcpListener::bind(http_addr)
        .await
        .expect("failed to bind HTTP port");

    tracing::info!("HTTP server on http://{http_addr}");

    let http_server = axum::serve(
        http_listener,
        http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    );

    if ws_tls_enabled {
        tls::ensure_self_signed_certs(&cert_path, &key_path)
            .expect("failed to ensure TLS certificates");

        let rustls_config = tls::load_rustls_config(&cert_path, &key_path)
            .await
            .expect("failed to load TLS config");

        tracing::info!("WS server on wss://{ws_addr}");

        let ws_server = axum_server::bind_rustls(ws_addr, rustls_config)
            .serve(ws::router(state).into_make_service_with_connect_info::<SocketAddr>());

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WSS server error: {e}"); }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down");
            }
        }
    } else {
        let ws_listener = TcpListener::bind(ws_addr)
            .await
            .expect("failed to bind WS port");

        tracing::info!("WS server on ws://{ws_addr}");

        let ws_server = axum::serve(
            ws_listener,
            ws::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        );

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WS server error: {e}"); }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down");
            }
        }
    }
}

async fn run_migrations_or_validate_schema(db: &PgPool) -> anyhow::Result<()> {
    match sqlx::migrate!("./migrations").run(db).await {
        Ok(()) => {
            tracing::info!("Database connected and migrations applied");
            Ok(())
        }
        Err(sqlx::migrate::MigrateError::VersionMismatch(version)) => {
            tracing::warn!(
                "Migration checksum mismatch for version {version}; validating the existing schema"
            );
            validate_existing_schema(db)
                .await
                .with_context(|| {
                    format!(
                        "migration {version} no longer matches the database and the existing schema is incompatible"
                    )
                })?;
            tracing::warn!(
                "Using the existing database schema despite migration checksum mismatch for version {version}"
            );
            Ok(())
        }
        Err(err) => Err(err).context("failed to run database migrations"),
    }
}

async fn validate_existing_schema(db: &PgPool) -> anyhow::Result<()> {
    for table in ["base_modules", "users", "log_entries", "scripts"] {
        ensure_table_exists(db, table).await?;
    }

    for (table, column) in [
        ("base_modules", "id"),
        ("base_modules", "name"),
        ("base_modules", "version"),
        ("base_modules", "author"),
        ("base_modules", "checksum"),
        ("base_modules", "buffer_capacity"),
        ("base_modules", "enabled"),
        ("base_modules", "skin_data_msgpack"),
        ("base_modules", "languages_json"),
        ("users", "id"),
        ("users", "username"),
        ("users", "auth_token"),
        ("users", "base_module_id"),
        ("users", "avatar_png"),
        ("users", "serial"),
        ("log_entries", "id"),
        ("log_entries", "user_id"),
        ("log_entries", "entry_id"),
        ("log_entries", "timestamp"),
        ("log_entries", "entry_type"),
        ("log_entries", "author"),
        ("scripts", "id"),
        ("scripts", "user_id"),
        ("scripts", "entry_id"),
        ("scripts", "name"),
        ("scripts", "content"),
    ] {
        ensure_column_exists(db, table, column).await?;
    }

    let languages_json_type: Option<String> = sqlx::query_scalar(
        "SELECT data_type
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'base_modules' AND column_name = 'languages_json'",
    )
    .fetch_optional(db)
    .await
    .context("failed to inspect public.base_modules.languages_json")?;

    match languages_json_type.as_deref() {
        Some("json") | Some("jsonb") => Ok(()),
        Some(other) => bail!(
            "public.base_modules.languages_json has unsupported type {other}; expected json or jsonb"
        ),
        None => bail!("missing column public.base_modules.languages_json"),
    }
}

async fn ensure_table_exists(db: &PgPool, table: &str) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )",
    )
    .bind(table)
    .fetch_one(db)
    .await
    .with_context(|| format!("failed to inspect table public.{table}"))?;

    if exists {
        Ok(())
    } else {
        bail!("missing table public.{table}")
    }
}

async fn ensure_column_exists(db: &PgPool, table: &str, column: &str) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
        )",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .with_context(|| format!("failed to inspect column public.{table}.{column}"))?;

    if exists {
        Ok(())
    } else {
        bail!("missing column public.{table}.{column}")
    }
}
