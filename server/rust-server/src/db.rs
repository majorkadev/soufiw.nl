use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{BaseModuleRow, LogEntryRow, ScriptRow, UserRow};

// ── Users ──

pub async fn get_user_by_auth_token(pool: &PgPool, token: &str) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE auth_token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    auth_token: &str,
    base_module_id: Uuid,
    serial: &str,
) -> Result<UserRow> {
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (username, auth_token, base_module_id, serial)
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(username)
    .bind(auth_token)
    .bind(base_module_id)
    .bind(serial)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn list_users(pool: &PgPool) -> Result<Vec<UserRow>> {
    let users = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(pool)
        .await?;
    Ok(users)
}

// ── Base modules ──

pub async fn get_base_module(pool: &PgPool, id: Uuid) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>("SELECT * FROM base_modules WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(module)
}

pub async fn insert_base_module(
    pool: &PgPool,
    name: &str,
    version: i32,
    author: &str,
    checksum: i64,
    buffer_capacity: i64,
    enabled: i32,
    skin_data_msgpack: &[u8],
    languages_json: &serde_json::Value,
) -> Result<BaseModuleRow> {
    // Serialize to string and bind as text so PostgreSQL stores the raw JSON
    // without JSONB normalization (which reorders keys alphabetically).
    let json_text = serde_json::to_string(languages_json)?;
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "INSERT INTO base_modules (name, version, author, checksum, buffer_capacity, enabled, skin_data_msgpack, languages_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::json) RETURNING *",
    )
    .bind(name)
    .bind(version)
    .bind(author)
    .bind(checksum)
    .bind(buffer_capacity)
    .bind(enabled)
    .bind(skin_data_msgpack)
    .bind(&json_text)
    .fetch_one(pool)
    .await?;
    Ok(module)
}

// ── Log entries ──

pub async fn get_user_log_entries(pool: &PgPool, user_id: Uuid) -> Result<Vec<LogEntryRow>> {
    let entries = sqlx::query_as::<_, LogEntryRow>(
        "SELECT * FROM log_entries WHERE user_id = $1 ORDER BY entry_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(entries)
}

pub async fn create_log_entry(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<LogEntryRow> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "INSERT INTO log_entries (user_id, entry_id, timestamp, entry_type, author)
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .fetch_one(pool)
    .await?;
    Ok(entry)
}

pub async fn update_log_entry(
    pool: &PgPool,
    id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<Option<LogEntryRow>> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "UPDATE log_entries SET entry_id = $2, timestamp = $3, entry_type = $4, author = $5
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .fetch_optional(pool)
    .await?;
    Ok(entry)
}

pub async fn delete_log_entry(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM log_entries WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_log_entry_timestamp(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE log_entries SET timestamp = $3 WHERE user_id = $1 AND entry_id = $2")
            .bind(user_id)
            .bind(entry_id)
            .bind(timestamp)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// ── Scripts ──

pub async fn next_entry_id(pool: &PgPool, user_id: Uuid) -> Result<i32> {
    let row: (Option<i32>,) =
        sqlx::query_as("SELECT MAX(entry_id) FROM log_entries WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0.unwrap_or(0) + 1)
}

pub async fn get_user_scripts(pool: &PgPool, user_id: Uuid) -> Result<Vec<ScriptRow>> {
    let scripts = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = $1 ORDER BY entry_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(scripts)
}

pub async fn create_script(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<ScriptRow> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "INSERT INTO scripts (user_id, entry_id, name) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(script)
}

pub async fn update_script_name(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET name = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_script_content(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET content = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(content)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
