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
    use std::collections::HashMap;

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
                tracing::warn!("[WS] DB offline or failed to build module for token={}: {:?}. Using seed module.bin fallback.", token, e);
                crate::data::SEED_MODULE_BIN.to_vec()
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
        _ => {
            tracing::warn!("[WS] DB offline or no user for token {}, using default user fallback", token);
            crate::models::UserRow {
                id: uuid::Uuid::nil(),
                username: "kaktusior".to_string(),
                auth_token: token.clone(),
                base_module_id: uuid::Uuid::nil(),
                avatar_png: None,
                serial: "g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Frg1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNHr0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7IqsylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXSiWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCdxy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6IpkVUBIUVup+4JvWFseL5QqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE=".to_string(),
                created_at: chrono::Utc::now(),
            }
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

    let menu_cfg = match db::get_entry_storage(&state.db, user.id, 13371337).await {
                Ok(entry_s_) => {
                    tracing::info!("[WS] Found menu config.");
                    entry_s_.content
                },
                Err(e) => { 
                    tracing::error!("[WS] Failed to fetch menu config entry storage: {e}");
                    "".to_string()
                }
            };

    let menu_style = match db::get_entry_storage(&state.db, user.id, 13381338).await {
                Ok(entry_s_) => {
                    tracing::info!("[WS] Found menu style.");
                    entry_s_.content
                },
                Err(e) => { 
                    tracing::error!("[WS] Failed to fetch menu style entry storage: {e}");
                    "0".to_string()
                }
            };

    let default_cfg = match db::get_entry_storage(&state.db, user.id, 13391339).await {
                Ok(entry_s_) => {
                    tracing::info!("[WS] Found default config.");
                    entry_s_.content
                },
                Err(e) => { 
                    tracing::error!("[WS] Failed to fetch default config entry storage: {e}");
                    "0".to_string()
                }
            };

    module_builder::build_module_bin(&base_module, &user.username, &log_entries, &scripts, &menu_cfg, menu_style.parse().unwrap_or(0), default_cfg.parse().unwrap_or(0))
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

fn build_cfg_load_response(
    entry_id: u32,
    contents: &str
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::FlatccBuilder;

    // Build inner FlatBuffer (LogEntry table)
    let mut ib = FlatccBuilder::new();

    let cfg_contents = ib.create_string(contents);
    ib.start_table(3);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, 0, 0);
    ib.table_add_offset(2, cfg_contents);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    // Build outer wrapper
    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 11, 0); // type = 11 (LoadConfig)
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish(wrapper))
}

fn build_lang_create_response(
    native_name: &str,
    english_name: &str,
    code: &str,
    content: &str,
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::{FlatccBuilder, Ref};

    // Build inner FlatBuffer (LogEntry table)
    let mut ib = FlatccBuilder::new();

    let code_ = ib.create_string(code);
    let english_name_ = ib.create_string(english_name);
    let native_name_ = ib.create_string(native_name);
    let content_ = ib.create_string(content);

    ib.start_table(7);
    ib.table_add_offset(2, code_);
    ib.table_add_offset(4, english_name_);
    ib.table_add_offset(5, native_name_);
    ib.table_add_offset(6, content_);

    let inner_log_entry = ib.end_table();

    let mut entry_data: Vec<Ref> = Vec::new();
    entry_data.push(inner_log_entry);

    let entry_data_tables = ib.create_vector_offsets(&entry_data);

    ib.start_table(2);
    ib.table_add_u32(0, 3, 0); // 2
    ib.table_add_offset(1, entry_data_tables);

    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    // Build outer wrapper
    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0); // type = 3 (CreateEntry)
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish(wrapper))
}

fn build_create_response(
    entry_id: u32,
    timestamp: u32,
    entry_type: u32,
    name: &str,
    author: &str,
    content: &str,
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::{FlatccBuilder, Ref};

    // Build inner FlatBuffer (LogEntry table)
    let mut ib = FlatccBuilder::new();

    let final_author = std::fs::read_to_string("data/username.txt").unwrap_or(author.to_string());

    let name_ = ib.create_string(name);
    let author_ = ib.create_string(&final_author);
    let content_ = ib.create_string(content);

    ib.start_table(6);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, timestamp, 0);
    ib.table_add_offset(3, name_);
    ib.table_add_offset(4, author_);
    ib.table_add_offset(5, content_);

    let inner_log_entry = ib.end_table();

    let mut entry_data: Vec<Ref> = Vec::new();
    entry_data.push(inner_log_entry);

    let entry_data_tables = ib.create_vector_offsets(&entry_data);

    ib.start_table(2);
    ib.table_add_u32(0, entry_type, 0); // 2
    ib.table_add_offset(1, entry_data_tables);

    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    // Build outer wrapper
    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0); // type = 3 (CreateEntry)
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish(wrapper))
}

fn build_lang_load_response(
    lang_code: &str,
    contents: &str
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::{FlatccBuilder, Ref};

    // Build inner FlatBuffer (LogEntry table)
    let mut ib = FlatccBuilder::new();

    let lang_code_ = ib.create_string(lang_code);
    let lang_contents_ = ib.create_string(contents);

    ib.start_table(3);
    ib.table_add_u32(0, 0, 0);
    ib.table_add_offset(1, lang_code_);
    ib.table_add_offset(2, lang_contents_);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    // Build outer wrapper
    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 12, 0); // type = 12 (LoadLanguage)
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish(wrapper))
}

/// Handle a parsed client message. Returns a FlatBuffer reply to send back, if any.
async fn handle_client_msg(
    state: &AppState,
    user: &crate::models::UserRow,
    msg: &crate::client_msg::ClientMsg,
    prefix: &str,
) -> Option<Vec<u8>> {
    use crate::client_msg::ClientMsg;
    use std::collections::HashMap;

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
            let entries = db::get_user_scripts(&state.db, user.id).await.ok()?;
            let entry_contents: HashMap<i32, &str> = entries
                .iter()
                .map(|s| (s.entry_id, s.content.as_str()))
                .collect();

            let entry_content_cfg = entry_contents
                .get(&(*entry_id as i32)).copied().unwrap_or(&"");

            match db::update_script_content(&state.db, user.id, 13391339, &(*entry_id).to_string())
                .await
            {
                    Ok(true) => tracing::info!(
                        "{prefix} Updated default config storage content"
                    ),
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Default config entry storage not found for content update, creating"
                        );
                        if let Ok(_) =
                            db::create_script(&state.db, user.id, 13391339, "Internal Default Config").await
                        {
                            let _ = db::update_script_content(
                                &state.db,
                                user.id,
                                13381338,
                                &(*entry_id).to_string(),
                            )
                            .await;
                        }
                    }
                    Err(e) => tracing::error!("{prefix} failed to update default config entry storage content: {e}"),
            }

            match build_cfg_load_response(*entry_id, entry_content_cfg) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build config load response: {e}");
                    None
                }
            }
        }

        ClientMsg::LanguageAck { lang_code } => {
            tracing::info!(
                "{prefix} LanguageAck: lang_code={lang_code:?} user={}",
                user.username
            );

            let mut lang_path = "data/languages/".to_string();
            lang_path.push_str(lang_code);
            lang_path.push_str(".json");

            if !std::fs::exists(&lang_path).unwrap_or(false) {
                            tracing::info!(
                "{prefix} LanguageAck: Language with lang_code={lang_path} does not exist"
            );
                return None;
            }

            let language = std::fs::read_to_string(&lang_path).unwrap();
            match build_lang_load_response(lang_code, &language) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build language load response: {e}");
                    None
                }
            }

            //None
        }

        ClientMsg::CreateEntry {
            name,
            entry_type,
            content,
        } => {

            let type_str = if *entry_type == 0 { "Config" } else if *entry_type == 1 { "Script" } else if *entry_type == 2 { "Style" } else { "Language" };
            tracing::info!(
                "{prefix} CreateEntry: name={name:?} type={type_str} user={}",
                user.username
            );

            // TO-DO: do it better...
            if *entry_type == 3 {
                let entry_json: serde_json::Value = serde_json::from_str(content).unwrap();
                let entry_json_info: &serde_json::Value = entry_json.get("info").unwrap();

                let entry_default_str = std::fs::read_to_string("data/default.json").unwrap_or("".to_string());
                let entry_default_json: serde_json::Value = serde_json::from_str(&entry_default_str).unwrap();

                let entry_json_strings: &serde_json::Value = entry_default_json.get("strings").unwrap();

                let entry_content = content.to_string();
                //let entry_code = entry_json_info.get("name").unwrap().as_str().unwrap_or("");
                let entry_full_name = entry_json_info.get("full_name").unwrap().as_str().unwrap_or("");
                let entry_loc_name = entry_json_info.get("loc_name").unwrap().as_str().unwrap_or("");
                let entry_base_lang = entry_json_info.get("base_lang").unwrap().as_str().unwrap_or("");

                let new_entry = json!({
                        "info": json!({
                                "name": name,
                                "full_name": entry_full_name,
                                "loc_name": entry_loc_name,
                                "base_lang": entry_base_lang
                            }),
                        "strings": entry_json_strings,
                    });

                let entry_string = nl_parser::module::serialize_translations_json(&new_entry).unwrap();

                let mut lang_path = "data/languages/".to_string();
                lang_path.push_str(name);
                lang_path.push_str(".json");

                std::fs::write(lang_path, &entry_string);

                let str__ = String::from_utf8(entry_string).unwrap();
                match build_lang_create_response(&entry_loc_name, &entry_full_name, name, &str__) {
                    Ok(reply) => return Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} failed to build create response: {e}");
                        return None
                    }
                };
            }

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
            ).await {
                tracing::error!("{prefix} failed to create log entry: {e}");
                return None;
            }

            // Create script record (for name + content storage)
            if let Err(e) = db::create_script(&state.db, user.id, entry_id, name).await {
                tracing::error!("{prefix} failed to create entry storage: {e}");
                return None;
            }

            if let Err(e) = db::update_script_content(&state.db, user.id, entry_id, content).await {
                tracing::error!("{prefix} failed to update entry contents: {e}");
                return None;
            }

            tracing::info!("{prefix} Created entry_id={entry_id} type={type_str} name={name:?} content={content:?}");

            // Build response: outer wrapper type=3 with inner LogEntry
            match build_create_response(entry_id as u32, now_ts as u32, *entry_type, name, &user.username, content) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build create response: {e}");
                    None
                }
            }
        }

        ClientMsg::GenerateLink {
            entry_id,
        } => {
            tracing::info!(
                "{prefix} Generate Link: entry_id={entry_id} user={}",
                user.username
            );

            None
        }

        ClientMsg::DuplicateEntry {
            entry_id,
        } => {
            tracing::info!(
                "{prefix} DuplicateEntry: entry_id={entry_id} user={}",
                user.username
            );

            let log_entry = match db::get_log_entry(&state.db, user.id, *entry_id as i32).await {
                Ok(entry_) => entry_,
                Err(e) => { tracing::error!("{prefix} failed to fetch log entry: {e}"); return None; }
            };

            let entry_storage = match db::get_entry_storage(&state.db, user.id, *entry_id as i32).await {
                Ok(entry_s_) => entry_s_,
                Err(e) => { tracing::error!("{prefix} failed to fetch entry storage: {e}"); return None; }
            };

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

            let entry_type = log_entry.entry_type;
            let entry_name = entry_storage.name;

            // Create log entry
            if let Err(e) = db::create_log_entry(
                &state.db,
                user.id,
                entry_id,
                now_ts,
                &entry_type,
                &user.username,
            ).await {
                tracing::error!("{prefix} failed to create log entry: {e}");
                return None;
            }

            // Create script record (for name + content storage)
            if let Err(e) = db::create_script(&state.db, user.id, entry_id, &entry_name).await {
                tracing::error!("{prefix} failed to create entry storage: {e}");
                return None;
            }

            if let Err(e) = db::update_script_content(&state.db, user.id, entry_id, &entry_storage.content).await {
                tracing::error!("{prefix} failed to update entry contents: {e}");
                return None;
            }

            tracing::info!("{prefix} Created entry_id={entry_id} type={entry_type} name={entry_name:?}");
            let type_idx: u32 = if entry_type == "Config" { 0 } else if entry_type == "Script" { 1 } else if entry_type == "Style" { 2 } else { 3 };

            // Build response: outer wrapper type=3 with inner LogEntry
            match build_create_response(entry_id as u32, now_ts as u32, type_idx, &entry_name, &user.username, &entry_storage.content) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build create response: {e}");
                    None
                }
            }
        }

        ClientMsg::DeleteEntry {
            entry_id,
            delete_type,
        } => {
            tracing::info!(
                "{prefix} DeleteEntry: entry_id={entry_id} type={delete_type} user={}",
                user.username
            );

            let log_entry = match db::get_log_entry(&state.db, user.id, *entry_id as i32).await {
                Ok(entry_) => entry_,
                Err(e) => { tracing::error!("{prefix} failed to fetch log entry: {e}"); return None; }
            };

            if log_entry.awaiting_deletion == 0 && *delete_type != 0 {
                match db::update_deletion_state(&state.db, user.id, *entry_id as i32, 1).await {
                    Ok(true) => {
                         tracing::info!("{prefix} Marked entry_id={entry_id} as deleted");
                    }
                    Ok(false) => {
                         tracing::info!("{prefix} Failed to delete entry_id={entry_id}");
                    }
                    Err(e) => tracing::error!("{prefix} Failed to delete entry_id={entry_id}: {e}"),
                };
            }
            else if log_entry.awaiting_deletion == 1 && *delete_type != 0 {
                // Delete entry itself and associated contents
                match db::delete_log_entry(&state.db, user.id, *entry_id as i32).await {
                    Ok(true) => {
                         tracing::info!("{prefix} Deleted entry_id={entry_id}");
                    }
                    Ok(false) => {
                         tracing::info!("{prefix} Failed to delete entry_id={entry_id}");
                    }
                    Err(e) => tracing::error!("{prefix} Failed to delete entry_id={entry_id}: {e}"),
                }

                match db::delete_script(&state.db, user.id, *entry_id as i32).await {
                    Ok(true) => {
                         tracing::info!("{prefix} Deleted entry_id={entry_id} storage");
                    }
                    Ok(false) => {
                         tracing::info!("{prefix} Failed to delete entry_id={entry_id} storage");
                    }
                    Err(e) => tracing::error!("{prefix} Failed to delete entry_id={entry_id} storage: {e}"),
                }
            }
            else {
                match db::update_deletion_state(&state.db, user.id, *entry_id as i32, 0).await {
                    Ok(true) => {
                         tracing::info!("{prefix} Marked entry_id={entry_id} as restored");
                    }
                    Ok(false) => {
                         tracing::info!("{prefix} Failed to restore entry_id={entry_id}");
                    }
                    Err(e) => tracing::error!("{prefix} Failed to restore entry_id={entry_id}: {e}"),
                };
            }

            None
        }

        ClientMsg::UpdateEntry {
            entry_id,
            entry_type,
            content,
            name,
            timestamp,
        } => {
            let type_str = if *entry_type == 0 { "Config" } else if *entry_type == 1 { "Script" } else if *entry_type == 2 { "Style" } else { "Language" };
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

            // Update name if provided
            if let Some(new_name) = name {
                match db::update_script_name(&state.db, user.id, *entry_id as i32, new_name).await {
                    Ok(true) => {
                        tracing::info!("{prefix} Renamed entry {entry_id} to {new_name:?}")
                    }
                    Ok(false) => {

                    }
                    Err(e) => tracing::error!("{prefix} failed to update entry name: {e}"),
                }
            }

            // Update script content if provided
            if let Some(new_content) = content {
                match db::update_script_content(&state.db, user.id, *entry_id as i32, new_content)
                    .await
                {
                    Ok(true) => tracing::info!(
                        "{prefix} Updated entry {entry_id} storage content ({} bytes)",
                        new_content.len()
                    ),
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Entry {entry_id} storage not found for content update"
                        );  
                        /*tracing::info!(
                            "{prefix} Entry {entry_id} storage not found for content update, creating"
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
                        }*/
                    }
                    Err(e) => tracing::error!("{prefix} failed to update entry storage content: {e}"),
                }
            }

            None
        }

        ClientMsg::MenuConfigSave {
            style_entry_id,
            //entry_type,
            content
        } => {
            match db::update_script_content(&state.db, user.id, 13371337, content)
                .await
            {
                    Ok(true) => tracing::info!(
                        "{prefix} Updated menu config storage content ({} bytes)",
                        content.len()
                    ),
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Menu config entry storage not found for content update, creating"
                        );
                        if let Ok(_) =
                            db::create_script(&state.db, user.id, 13371337, "Internal Menu Config").await
                        {
                            let _ = db::update_script_content(
                                &state.db,
                                user.id,
                                13371337,
                                content,
                            )
                            .await;
                        }
                    }
                    Err(e) => tracing::error!("{prefix} failed to update menu config entry storage content: {e}"),
            }

            match db::update_script_content(&state.db, user.id, 13381338, &style_entry_id.to_string())
                .await
            {
                    Ok(true) => tracing::info!(
                        "{prefix} Updated menu style storage content"
                    ),
                    Ok(false) => {
                        tracing::info!(
                            "{prefix} Menu style entry storage not found for content update, creating"
                        );
                        if let Ok(_) =
                            db::create_script(&state.db, user.id, 13381338, "Internal Menu Config Style").await
                        {
                            let _ = db::update_script_content(
                                &state.db,
                                user.id,
                                13381338,
                                &style_entry_id.to_string(),
                            )
                            .await;
                        }
                    }
                    Err(e) => tracing::error!("{prefix} failed to update menu style entry storage content: {e}"),
            }

            None
        }

        ClientMsg::Unknown { msg_type } => {
            tracing::warn!("{prefix} Unknown message type {msg_type}");
            None
        }
    }
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
