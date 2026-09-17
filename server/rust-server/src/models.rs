use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub auth_token: String,
    pub base_module_id: Uuid,
    pub avatar_png: Option<Vec<u8>>,
    pub serial: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BaseModuleRow {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub author: String,
    pub checksum: i64,
    pub buffer_capacity: i64,
    pub enabled: i32,
    pub skin_data_msgpack: Vec<u8>,
    pub languages_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogEntryRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub entry_id: i32,
    pub timestamp: i32,
    pub entry_type: String,
    pub author: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScriptRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub entry_id: i32,
    pub name: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
