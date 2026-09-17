use std::net::SocketAddr;

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::any,
};
use serde_json::json;

use crate::config::{AUTH_DATA, AUTH_MESSAGE};
use crate::data::KEY_BIN;
use crate::{AppState, db, module_builder};

pub fn router(state: AppState) -> Router {
    Router::new().fallback(any(ws_upgrade)).with_state(state)
}

async fn ws_upgrade(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    tracing::info!("[WS] New WebSocket upgrade request from {}", addr);
    ws.max_message_size(50 * 1024 * 1024)
        .on_upgrade(move |socket| handle_ws(socket, state, addr))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, addr: SocketAddr) {
    tracing::info!(
        "[WS] Connection established from {}, waiting for first message...",
        addr
    );

    // Wait for client's first message — contains "token\nclient\ngame"
    let first = socket.recv().await;
    let token = match first {
        Some(Ok(ref msg)) => {
            tracing::info!("[WS] <- First message: {}", msg_summary(msg));
            match msg {
                Message::Text(t) => t.lines().next().unwrap_or("").trim().to_string(),
                _ => String::new(),
            }
        }
        Some(Err(e)) => {
            tracing::warn!("[WS] <- Recv error on first message: {e}");
            return;
        }
        None => {
            tracing::info!("[WS] <- Client disconnected before sending");
            return;
        }
    };

    if token.is_empty() {
        tracing::warn!("[WS] No token found in first message, closing");
        return;
    }

    tracing::info!("[WS] Token from first message: {token}");

    // Store IP → token mapping for avatar lookups
    state
        .ip_tokens
        .write()
        .await
        .insert(addr.ip(), token.clone());
    tracing::info!("[WS] Stored IP→token mapping: {} → {}", addr.ip(), token);

    // Frame 1: Auth JSON
    let auth = json!({
        "Type": "Auth",
        "Message": AUTH_MESSAGE,
        "Data": AUTH_DATA,
    });
    tracing::info!("[WS] -> Auth JSON: {}", auth);
    if socket
        .send(Message::Text(auth.to_string().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send auth frame");
        return;
    }

    // Frame 2: module blob — raw file override or build from DB
    let module_bin = if let Some(ref raw) = state.raw_module {
        tracing::info!("[WS] Using raw module override ({} bytes)", raw.len());
        raw.clone()
    } else {
        match build_user_module(&state, &token).await {
            Ok(bin) => bin,
            Err(e) => {
                tracing::error!("[WS] Failed to build module for token={}: {:?}", token, e);
                return;
            }
        }
    };

    tracing::info!("[WS] -> Module blob ({} bytes)", module_bin.len());
    if socket
        .send(Message::Binary(module_bin.into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send module blob");
        return;
    }

    // Frame 3: Key blob
    tracing::info!("[WS] -> Key blob ({} bytes)", KEY_BIN.len());
    if socket
        .send(Message::Binary(KEY_BIN.to_vec().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send key blob");
        return;
    }

    tracing::info!("[WS] All 3 frames sent, processing client messages...");

    // Look up user for DB operations
    let user = match db::get_user_by_auth_token(&state.db, &token).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!("[WS] No user for token {}, will log but not persist", token);
            drain_messages(&mut socket).await;
            return;
        }
        Err(e) => {
            tracing::error!("[WS] DB error looking up user: {e}");
            drain_messages(&mut socket).await;
            return;
        }
    };

    let mut msg_count = 0u32;
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(msg) => {
                if matches!(msg, Message::Close(_)) {
                    tracing::info!("[WS] <- Close: {}", msg_summary(&msg));
                    break;
                }
                msg_count += 1;

                if let Message::Binary(ref data) = msg {
                    handle_binary_msg(&state, &user, data, msg_count, &mut socket).await;
                } else {
                    tracing::info!("[WS] <- Msg #{}: {}", msg_count, msg_summary(&msg));
                }
            }
            Err(e) => {
                tracing::warn!("[WS] <- Error: {e}");
                break;
            }
        }
    }

    tracing::info!(
        "[WS] Disconnected (received {} post-auth messages)",
        msg_count
    );
}

async fn build_user_module(state: &AppState, token: &str) -> anyhow::Result<Vec<u8>> {
    let user = db::get_user_by_auth_token(&state.db, token)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no user found for token"))?;

    let base_module = db::get_base_module(&state.db, user.base_module_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("base module not found"))?;

    let log_entries = db::get_user_log_entries(&state.db, user.id).await?;
    let scripts = db::get_user_scripts(&state.db, user.id).await?;

    module_builder::build_module_bin(&base_module, &user.username, &log_entries, &scripts)
}

async fn drain_messages(socket: &mut WebSocket) {
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(msg) if matches!(msg, Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }
}

async fn handle_binary_msg(
    state: &AppState,
    user: &crate::models::UserRow,
    data: &[u8],
    msg_num: u32,
    socket: &mut WebSocket,
) {
    use nl_parser::pipeline;

    let prefix = format!("[WS] Msg #{msg_num}");

    // Decrypt + decompress
    let decompressed = match pipeline::decrypt(data) {
        Ok(decrypted) => match pipeline::decompress(&decrypted) {
            Ok(d) => d,
            Err(_) => {
                tracing::debug!("{prefix} decrypt ok but decompress failed");
                return;
            }
        },
        Err(_) => {
            tracing::debug!("{prefix} decrypt failed, ignoring");
            return;
        }
    };

    // Parse as client message
    match crate::client_msg::parse(&decompressed) {
        Ok(msg) => {
            tracing::info!("{prefix} parsed: {msg:?}");
            let reply = handle_client_msg(state, user, &msg, &prefix).await;
            if let Some(reply_bytes) = reply {
                send_reply(socket, &reply_bytes, &prefix).await;
            }
        }
        Err(e) => {
            tracing::warn!(
                "{prefix} parse error: {e}, hex: {}",
                hex_preview(&decompressed, 128)
            );
        }
    }
}

async fn send_reply(socket: &mut WebSocket, flatbuffer: &[u8], prefix: &str) {
    use nl_parser::pipeline;
    let compressed = pipeline::compress(flatbuffer);
    match pipeline::encrypt(&compressed) {
        Ok(encrypted) => {
            tracing::info!(
                "{prefix} -> Reply ({} bytes plaintext, {} encrypted)",
                flatbuffer.len(),
                encrypted.len()
            );
            if socket
                .send(Message::Binary(encrypted.into()))
                .await
                .is_err()
            {
                tracing::error!("{prefix} Failed to send reply");
            }
        }
        Err(e) => {
            tracing::error!("{prefix} Failed to encrypt reply: {e}");
        }
    }
}

/// Handle a parsed client message. Returns a FlatBuffer reply to send back, if any.
async fn handle_client_msg(
    state: &AppState,
    user: &crate::models::UserRow,
    msg: &crate::client_msg::ClientMsg,
    prefix: &str,
) -> Option<Vec<u8>> {
    use crate::client_msg::ClientMsg;

    match msg {
        ClientMsg::Init { steam_id } => {
            tracing::info!("{prefix} Init: steam_id={steam_id} user={}", user.username);
            None
        }

        ClientMsg::ConfigAck { entry_id } => {
            tracing::info!(
                "{prefix} ConfigAck: entry_id={entry_id} user={}",
                user.username
            );
            None
        }

        ClientMsg::CreateEntry {
            name,
            entry_type,
            expected_count,
        } => {
            let type_str = if *entry_type == 1 { "Script" } else { "Config" };
            tracing::info!(
                "{prefix} CreateEntry: name={name:?} type={type_str} expected_count={expected_count} user={}",
                user.username
            );

            // Assign next entry_id
            let entry_id = match db::next_entry_id(&state.db, user.id).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} failed to get next entry_id: {e}");
                    return None;
                }
            };

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i32;

            // Create log entry
            if let Err(e) = db::create_log_entry(
                &state.db,
                user.id,
                entry_id,
                now_ts,
                type_str,
                &user.username,
            )
            .await
            {
                tracing::error!("{prefix} failed to create log entry: {e}");
                return None;
            }

            // Create script record (for name + content storage)
            if *entry_type == 1 {
                if let Err(e) = db::create_script(&state.db, user.id, entry_id, name).await {
                    tracing::error!("{prefix} failed to create script: {e}");
                    return None;
                }
            }

            tracing::info!("{prefix} Created entry_id={entry_id} type={type_str} name={name:?}");

            // Build response: outer wrapper type=3 with inner LogEntry
            match build_create_response(entry_id as u32, now_ts as u32, type_str, &user.username) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build create response: {e}");
                    None
                }
            }
        }

        ClientMsg::UpdateEntry {
            entry_id,
            entry_type,
            content,
            name,
            timestamp,
        } => {
            let type_str = if *entry_type == 1 { "Script" } else { "Config" };
            tracing::info!(
                "{prefix} UpdateEntry: entry_id={entry_id} type={type_str} name={name:?} content_len={} ts={timestamp:?} user={}",
                content.as_ref().map(|c| c.len()).unwrap_or(0),
                user.username
            );

            // Update log entry timestamp if provided
            if let Some(ts) = timestamp {
                if let Err(e) =
                    db::update_log_entry_timestamp(&state.db, user.id, *entry_id as i32, *ts as i32)
                        .await
                {
                    tracing::error!("{prefix} failed to update log entry timestamp: {e}");
                }
            }

            // Update script name if provided
            if let Some(new_name) = name {
                match db::update_script_name(&state.db, user.id, *entry_id as i32, new_name).await {
                    Ok(true) => {
                        tracing::info!("{prefix} Renamed script {entry_id} to {new_name:?}")
                    }
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Script {entry_id} not found, creating with name {new_name:?}"
                        );
                        let _ =
                            db::create_script(&state.db, user.id, *entry_id as i32, new_name).await;
                    }
                    Err(e) => tracing::error!("{prefix} failed to update script name: {e}"),
                }
            }

            // Update script content if provided
            if let Some(new_content) = content {
                match db::update_script_content(&state.db, user.id, *entry_id as i32, new_content)
                    .await
                {
                    Ok(true) => tracing::info!(
                        "{prefix} Updated script {entry_id} content ({} bytes)",
                        new_content.len()
                    ),
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Script {entry_id} not found for content update, creating"
                        );
                        if let Ok(_) =
                            db::create_script(&state.db, user.id, *entry_id as i32, "").await
                        {
                            let _ = db::update_script_content(
                                &state.db,
                                user.id,
                                *entry_id as i32,
                                new_content,
                            )
                            .await;
                        }
                    }
                    Err(e) => tracing::error!("{prefix} failed to update script content: {e}"),
                }
            }

            None
        }

        ClientMsg::Unknown { msg_type } => {
            tracing::warn!("{prefix} Unknown message type {msg_type}");
            None
        }
    }
}

/// Build a response FlatBuffer for a CreateEntry.
///
/// Outer wrapper: { type: u32 = 3 (field 0), payload: [u8] (field 1) }
/// Inner (LogEntry-like): { entry_id: u32 (field 0), timestamp: u32 (field 1),
///                          entry_type: string (field 3), author: string (field 4) }
fn build_create_response(
    entry_id: u32,
    timestamp: u32,
    entry_type: &str,
    author: &str,
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::FlatccBuilder;

    // Build inner FlatBuffer (LogEntry table)
    let mut ib = FlatccBuilder::new();
    let et = ib.create_string(entry_type);
    let au = ib.create_string(author);
    ib.start_table(5);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, timestamp, 0);
    ib.table_add_offset(3, et);
    ib.table_add_offset(4, au);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    // Build outer wrapper
    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0); // type = 3 (CreateEntry)
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

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

fn msg_summary(msg: &Message) -> String {
    match msg {
        Message::Text(t) => {
            let s = t.as_str();
            if s.len() > 200 {
                format!("text({}B): {}...", s.len(), &s[..200])
            } else {
                format!("text({}B): {s}", s.len())
            }
        }
        Message::Binary(b) => {
            let hex_preview: String = b
                .iter()
                .take(32)
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(" ");
            format!("binary({}B): {}", b.len(), hex_preview)
        }
        Message::Ping(b) => format!("ping({}B)", b.len()),
        Message::Pong(b) => format!("pong({}B)", b.len()),
        Message::Close(c) => format!("close({c:?})"),
    }
}
