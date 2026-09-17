use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::config::{self, DEFAULT_SERIAL};
use crate::data::{DEFAULT_AVATAR_PNG, SEED_MODULE_BIN};
use crate::error::AppError;
use crate::{AppState, db};

pub fn router(state: AppState) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("Express"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        ));

    Router::new()
        .route("/api/config", get(config_handler))
        .route("/api/getavatar", get(avatar_handler))
        .route("/getavatar", get(avatar_handler))
        .route("/api/sendlog", get(sendlog_handler))
        .route("/sendlog", get(sendlog_handler))
        .route("/lua/{name}", get(lua_handler))
        // Admin endpoints
        .route("/admin/seed", post(admin_seed))
        .route(
            "/admin/users",
            post(admin_create_user).get(admin_list_users),
        )
        .route(
            "/admin/users/{id}/logs",
            get(admin_get_logs).post(admin_create_log),
        )
        .route(
            "/admin/users/{user_id}/logs/{log_id}",
            axum::routing::put(admin_update_log).delete(admin_delete_log),
        )
        .fallback(fallback_handler)
        .layer(middleware)
        .with_state(state)
}

async fn config_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /api/config params={:?}", params);
    let resp = json!({
        "status": "ok",
        "version": "2.0",
        "update": false,
        "config": {
            "glow": true,
            "esp": true,
            "aimbot": true,
            "misc": true,
        }
    });
    tracing::debug!("[HTTP] -> config response: {}", resp);
    axum::Json(resp)
}

async fn avatar_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let size = params.get("size").cloned().unwrap_or_default();
    let token = params.get("token").cloned().unwrap_or_default();
    tracing::info!(
        "[HTTP] GET /api/getavatar size={} token={} from={}",
        size,
        token,
        addr
    );

    // Look up auth_token via IP→token mapping from the last WS connection
    let auth_token = state.ip_tokens.read().await.get(&addr.ip()).cloned();

    if let Some(ref auth_token) = auth_token {
        tracing::debug!(
            "[HTTP] IP {} mapped to auth_token {}",
            addr.ip(),
            auth_token
        );
        if let Ok(Some(user)) = db::get_user_by_auth_token(&state.db, auth_token).await {
            if let Some(avatar) = user.avatar_png {
                tracing::debug!(
                    "[HTTP] -> per-user avatar PNG ({} bytes) for {}",
                    avatar.len(),
                    user.username
                );
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "image/png")
                    .body(Body::from(avatar))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        }
    } else {
        tracing::debug!("[HTTP] No IP→token mapping for {}", addr.ip());
    }

    tracing::debug!(
        "[HTTP] -> default avatar PNG ({} bytes)",
        DEFAULT_AVATAR_PNG.len()
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(DEFAULT_AVATAR_PNG))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn sendlog_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /api/sendlog params={:?}", params);
    tracing::debug!("[HTTP] -> sendlog OK");
    axum::Json(json!({"status": "ok"}))
}

async fn lua_handler(
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /lua/{} params={:?}", name, params);
    let body = format!("-- lua library: {name}\n");
    tracing::debug!("[HTTP] -> lua response ({} bytes)", body.len());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn fallback_handler(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_owned()))
        .collect();

    tracing::info!(
        "[HTTP] {} {} query={} headers={:?}",
        method,
        path,
        query,
        headers
    );

    // Check for POST with type:4 auth body → per-user serial
    if method == axum::http::Method::POST {
        let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("[HTTP] Failed to read POST body: {e}");
                return express_404(method.as_str(), &path);
            }
        };

        // Try as JSON first
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            tracing::info!("[HTTP] POST JSON ({} bytes): {}", body_bytes.len(), val);
            if val.get("type").and_then(|t| t.as_i64()) == Some(4) {
                let token = val.get("token").and_then(|t| t.as_str()).unwrap_or("");
                let serial = if !token.is_empty() {
                    match db::get_user_by_auth_token(&state.db, token).await {
                        Ok(Some(user)) => user.serial,
                        _ => String::new(),
                    }
                } else {
                    String::new()
                };

                tracing::info!(
                    "[HTTP] -> GetSerial (type=4), returning serial ({} bytes)",
                    serial.len()
                );
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from(serial))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        } else {
            // Not JSON — log raw and try decrypt+decompress
            tracing::info!(
                "[HTTP] POST binary ({} bytes): {}",
                body_bytes.len(),
                hex_preview(&body_bytes, 64)
            );
            try_decrypt_and_log("[HTTP] POST", &body_bytes);
        }
    }

    tracing::warn!("[HTTP] -> 404 (unknown route)");
    express_404(method.as_str(), &path)
}

fn express_404(method: &str, path: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n<title>Error</title>\n\
         </head>\n<body>\n\
         <pre>Cannot {method} {path}</pre>\n\
         </body>\n</html>\n"
    );
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'")
        .header("x-content-type-options", "nosniff")
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── Decryption helpers ──

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let preview: String = data
        .iter()
        .take(max_bytes)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > max_bytes {
        format!("{}... ({} bytes total)", preview, data.len())
    } else {
        preview
    }
}

fn try_decrypt_and_log(prefix: &str, data: &[u8]) {
    use nl_parser::module::Module;
    use nl_parser::pipeline;

    // Try AES decrypt only
    match pipeline::decrypt(data) {
        Ok(decrypted) => {
            tracing::info!(
                "{} decrypted ({} bytes): {}",
                prefix,
                decrypted.len(),
                hex_preview(&decrypted, 64)
            );
            // Try LZ4 decompress
            match pipeline::decompress(&decrypted) {
                Ok(decompressed) => {
                    tracing::info!("{} decompressed ({} bytes)", prefix, decompressed.len());
                    // Try as UTF-8 text
                    if let Ok(text) = std::str::from_utf8(&decompressed) {
                        let preview = if text.len() > 1000 {
                            format!("{}...", &text[..1000])
                        } else {
                            text.to_string()
                        };
                        tracing::info!("{} plaintext: {}", prefix, preview);
                    }
                    // Try as FlatBuffer module
                    match Module::from_flatbuffer(&decompressed) {
                        Ok(module) => {
                            tracing::info!(
                                "{} parsed as Module: version={} author={} token={} checksum={} enabled={} config_log={} script_log={} languages={}",
                                prefix,
                                module.version,
                                module.author,
                                module.auth_token,
                                module.checksum,
                                module.enabled,
                                module.config_log.len(),
                                module.script_log.len(),
                                module.languages.len(),
                            );
                        }
                        Err(_) => {
                            tracing::debug!(
                                "{} not a valid Module FlatBuffer, raw hex: {}",
                                prefix,
                                hex_preview(&decompressed, 128)
                            );
                        }
                    }
                }
                Err(_) => {
                    // Not LZ4 — just show decrypted as text or hex
                    if let Ok(text) = std::str::from_utf8(&decrypted) {
                        let preview = if text.len() > 1000 {
                            format!("{}...", &text[..1000])
                        } else {
                            text.to_string()
                        };
                        tracing::info!("{} decrypted text: {}", prefix, preview);
                    }
                }
            }
        }
        Err(_) => {
            tracing::debug!("{} not AES-encrypted (decrypt failed)", prefix);
        }
    }
}

// ── Admin endpoints ──

async fn admin_seed(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    use nl_parser::module::Module;
    use nl_parser::pipeline;

    tracing::info!("[HTTP] POST /admin/seed — parsing SEED_MODULE_BIN");

    let flat = pipeline::load_module(SEED_MODULE_BIN)?;
    let module = Module::from_flatbuffer(&flat)?;

    // Extract raw skin_data bytes directly from FlatBuffer (no struct round-trip)
    let skin_data_msgpack = Module::extract_raw_skin_data(&flat)?;
    let languages_json = serde_json::to_value(&module.languages)?;

    let base = db::insert_base_module(
        &state.db,
        "default",
        module.version as i32,
        &module.author,
        module.checksum as i64,
        module.buffer_capacity as i64,
        module.enabled as i32,
        &skin_data_msgpack,
        &languages_json,
    )
    .await?;

    // Create default user from the module's author + hardcoded default token
    let user = db::create_user(
        &state.db,
        &module.author,
        config::DEFAULT_USER_TOKEN,
        base.id,
        DEFAULT_SERIAL,
    )
    .await?;

    // Seed that user's log entries from the module
    for (entry_type, entries) in [
        ("Config", &module.config_log),
        ("Script", &module.script_log),
    ] {
        for entry in entries {
            db::create_log_entry(
                &state.db,
                user.id,
                entry.entry_id as i32,
                entry.timestamp as i32,
                entry_type,
                &entry.author,
            )
            .await?;

            // Seed script records with their names
            if entry_type == "Script" {
                let _ =
                    db::create_script(&state.db, user.id, entry.entry_id as i32, &entry.name).await;
            }
        }
    }

    tracing::info!(
        "[HTTP] -> Seed complete, base_module id={}, user id={} ({})",
        base.id,
        user.id,
        user.username
    );
    Ok(axum::Json(json!({
        "status": "ok",
        "base_module_id": base.id,
        "user_id": user.id,
        "username": user.username,
        "auth_token": user.auth_token,
        "version": base.version,
    })))
}

#[derive(Deserialize)]
struct CreateUserReq {
    username: String,
    auth_token: String,
    base_module_id: Uuid,
    #[serde(default)]
    serial: String,
}

async fn admin_create_user(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CreateUserReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] POST /admin/users username={}", req.username);
    let user = db::create_user(
        &state.db,
        &req.username,
        &req.auth_token,
        req.base_module_id,
        &req.serial,
    )
    .await?;
    Ok((StatusCode::CREATED, axum::Json(json!(user))))
}

async fn admin_list_users(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] GET /admin/users");
    let users = db::list_users(&state.db).await?;
    Ok(axum::Json(json!(users)))
}

async fn admin_get_logs(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] GET /admin/users/{}/logs", id);
    let logs = db::get_user_log_entries(&state.db, id).await?;
    Ok(axum::Json(json!(logs)))
}

#[derive(Deserialize)]
struct CreateLogReq {
    entry_id: i32,
    timestamp: i32,
    entry_type: String,
    author: String,
}

async fn admin_create_log(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    axum::Json(req): axum::Json<CreateLogReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] POST /admin/users/{}/logs", user_id);
    let entry = db::create_log_entry(
        &state.db,
        user_id,
        req.entry_id,
        req.timestamp,
        &req.entry_type,
        &req.author,
    )
    .await?;
    Ok((StatusCode::CREATED, axum::Json(json!(entry))))
}

#[derive(Deserialize)]
struct UpdateLogReq {
    entry_id: i32,
    timestamp: i32,
    entry_type: String,
    author: String,
}

async fn admin_update_log(
    State(state): State<AppState>,
    Path((user_id, log_id)): Path<(Uuid, Uuid)>,
    axum::Json(req): axum::Json<UpdateLogReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] PUT /admin/users/{}/logs/{}", user_id, log_id);
    let entry = db::update_log_entry(
        &state.db,
        log_id,
        req.entry_id,
        req.timestamp,
        &req.entry_type,
        &req.author,
    )
    .await?;
    match entry {
        Some(e) => Ok(axum::Json(json!(e)).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn admin_delete_log(
    State(state): State<AppState>,
    Path((user_id, log_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] DELETE /admin/users/{}/logs/{}", user_id, log_id);
    let deleted = db::delete_log_entry(&state.db, log_id).await?;
    if deleted {
        Ok(axum::Json(json!({"status": "deleted"})).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
