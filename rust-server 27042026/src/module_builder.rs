use anyhow::{Context, Result};
use nl_parser::flatcc_builder::{FlatccBuilder, Ref};
use nl_parser::module::{Language, LogEntry, serialize_translations_json};
use nl_parser::pipeline;

use std::collections::HashMap;

use crate::config;
use crate::models::{BaseModuleRow, LogEntryRow, ScriptRow};

pub fn build_module_bin(
    base: &BaseModuleRow,
    username: &str,
    log_entries: &[LogEntryRow],
    scripts: &[ScriptRow],
    menu_cfg: &str,
    menu_style: u32,
    default_cfg: u32,
) -> Result<Vec<u8>> {
    let languages: Vec<Language> = serde_json::from_value(base.languages_json.clone())
        .context("deserialize languages from DB")?;

    // Build entry_id → script name lookup
    let script_names: HashMap<i32, &str> = scripts
        .iter()
        .map(|s| (s.entry_id, s.name.as_str()))
        .collect();

    let mut config_log = Vec::new();
    let mut script_log = Vec::new();
    let mut style_log = Vec::new();
    for entry in log_entries {
        // Use script name from DB if available, otherwise fall back to entry_type
        let name = script_names
            .get(&entry.entry_id)
            .copied()
            .unwrap_or(&entry.entry_type);
        let entry_author = std::fs::read_to_string("data/username.txt").unwrap_or(entry.author.clone());
        let log_entry = LogEntry {
            entry_id: entry.entry_id as u32,
            timestamp: entry.timestamp as u32,
            awaiting_deletion: entry.awaiting_deletion as u32,
            name: name.to_string(),
            author: entry_author,
        };
        match entry.entry_type.as_str() {
            "Config" => config_log.push(log_entry),
            "Script" => script_log.push(log_entry),
            "Style" => style_log.push(log_entry),
            _ => {}
        }
    }

    let final_username = std::fs::read_to_string("data/username.txt").unwrap_or(username.to_string());
    let inner_bytes = build_inner_flatbuffer(base, &final_username, &config_log, &style_log, &script_log, &languages, scripts, menu_cfg, menu_style, default_cfg)?;

    // Outer wrapper with force_defaults for version=0
    let mut ob = FlatccBuilder::new();
    ob.force_defaults(true);
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, base.version as u32, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();

    let flatbuffer_bytes = ob.finish(wrapper);
    let encrypted = pipeline::save_module(&flatbuffer_bytes).context("encrypt module")?;

    Ok(encrypted)
}

struct LangStrings {
    code: Ref,
    english_name: Ref,
    native_name: Ref,
    translations: Option<Ref>,
}

fn build_inner_flatbuffer(
    base: &BaseModuleRow,
    username: &str,
    config_log: &[LogEntry],
    style_log: &[LogEntry],
    script_log: &[LogEntry],
    languages: &[Language],
    scripts: &[ScriptRow],
    menu_cfg: &str,
    menu_style: u32,
    default_cfg: u32,
) -> Result<Vec<u8>> {
    use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};

    let mut b = FlatccBuilder::new();

    // === PHASE 1: Log entries (created FIRST = highest buffer positions) ===
    // Config entries get 8 bytes of gap padding before their table
    let config_offsets: Vec<_> = config_log
        .iter()
        .map(|e| build_log_entry_with_gap(&mut b, e, 8))
        .collect();
    let script_offsets: Vec<_> = script_log
        .iter()
        .map(|e| build_log_entry(&mut b, e, scripts))
        .collect();
    let style_offsets: Vec<_> = style_log
        .iter()
        .map(|e| build_log_entry(&mut b, e, scripts))
        .collect();

    // === PHASE 2: Language STRING DATA only (no tables yet) ===
    let mut lang_data: Vec<LangStrings> = Vec::new();
    for lang in languages {
        let translations = match &lang.translations {
            Some(value) => {
                let json_bytes = serialize_translations_json(value)?;
                let json_str = std::str::from_utf8(&json_bytes)
                    .map_err(|e| anyhow::anyhow!("translations JSON not UTF-8: {e}"))?;
                Some(b.create_string(json_str))
            }
            None => None,
        };
        let code = b.create_string(&lang.code);
        let english_name = b.create_string(&lang.english_name);
        let native_name = if lang.native_name == lang.english_name {
            english_name
        } else {
            b.create_string(&lang.native_name)
        };
        lang_data.push(LangStrings {
            code,
            english_name,
            native_name,
            translations,
        });
    }

    let entries = std::fs::read_dir("data/languages/").unwrap();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let entry_content = std::fs::read_to_string(entry.path()).unwrap_or("".to_string());
                let entry_json: serde_json::Value = serde_json::from_str(&entry_content).unwrap();
                let entry_json_info: &serde_json::Value = entry_json.get("info").unwrap();

                let entry_content_ = b.create_string(&entry_content);
                let entry_code = entry_json_info.get("name").unwrap().as_str().unwrap_or("en");

                if entry_code != "en" {
                    let entry_code_ = b.create_string(&entry_code);
                    let entry_full_name = b.create_string(&entry_json_info.get("full_name").unwrap().to_string());
                    let entry_loc_name = b.create_string(&entry_json_info.get("loc_name").unwrap().to_string());

                    lang_data.push(LangStrings {
                        code: entry_code_,
                        english_name: entry_full_name,
                        native_name: entry_loc_name,
                        translations: Some(entry_content_),
                    });
                }
            }
            Err(e) => {
                
            }
        }
    }

    // === PHASE 3: extra_data (empty vec) ===
    // 4 bytes of alignment padding before extra_data
    b.push_zeros(4);
    let extra_data = b.create_string(menu_cfg);

    // === PHASE 3.5: Orphaned "admin" string ===
    // The C++ builder creates a default author "admin" that ends up unreferenced.
    let _orphaned_admin = b.create_string("admin");

    // === PHASE 4: skin_data (raw MsgPack bytes from DB) ===
    let skin_data = b.create_vector_u8(&base.skin_data_msgpack);

    // === PHASE 5: auth_token string ===
    let auth_token = b.create_string(config::MODULE_AUTH_TOKEN);

    // === PHASE 6: Language TABLES (referencing strings from Phase 2) ===
    // Creation order [0, 3, 2, 1, 4] matches the original builder so that
    // lang[3] absorbs 2-byte alignment padding from lang[0]'s 18-byte vtable.
    let lang_offsets = if lang_data.len() == 5 {
        let creation_order: &[usize] = &[0, 3, 2, 1, 4];
        let mut offsets = vec![Ref::dummy(); lang_data.len()];
        for &idx in creation_order {
            offsets[idx] = build_lang_table(&mut b, &lang_data[idx]);
        }
        offsets
    } else {
        // Fallback: sequential order for non-standard language counts
        lang_data
            .iter()
            .map(|ls| build_lang_table(&mut b, ls))
            .collect()
    };

    // === PHASE 7: Vector offset arrays ===
    let lang_vec = b.create_vector_offsets(&lang_offsets);
    let style_vec = b.create_vector_offsets(&style_offsets);
    let script_vec = b.create_vector_offsets(&script_offsets);
    let config_vec = b.create_vector_offsets(&config_offsets);

    let last_style: u32 = menu_style;
    let mut expiration_time = base.checksum as u32;

    if std::fs::exists("data/subscription_end_date.txt").unwrap_or(false) {
        let sub_time_identifier = std::fs::read_to_string("data/subscription_end_date.txt").unwrap_or("2050-04-15 07:00:00 UTC".to_string());

        let default_sub_time = NaiveDateTime::from_timestamp(expiration_time as i64, 0);
        let sub_time_parsed: DateTime<Utc> = sub_time_identifier.parse().unwrap_or(DateTime::from_utc(default_sub_time, Utc));
        expiration_time = sub_time_parsed.timestamp() as u32;
    }

    // === PHASE 8+9: Root table with INLINE author string ===
    b.start_table(13);
    b.table_add_offset(4, config_vec);
    b.table_add_offset(5, script_vec);
    b.table_add_offset(6, style_vec);
    b.table_add_offset(7, lang_vec);
    b.table_add_offset(1, extra_data);
    let author = b.create_string(username); // INLINE
    b.table_add_offset(2, author);
    b.table_add_offset(9, skin_data);
    b.table_add_u32(3, expiration_time, 0);
    b.table_add_u32(8, last_style, 0);
    b.table_add_offset(11, auth_token);
    b.table_add_u32(0, default_cfg, 0);
    let root = b.end_table();
    Ok(b.finish_minimal(root))
}

fn build_lang_table(b: &mut FlatccBuilder, ls: &LangStrings) -> Ref {
    b.start_table(7);
    b.table_add_offset(2, ls.code);
    b.table_add_offset(4, ls.english_name);
    b.table_add_offset(5, ls.native_name);
    if let Some(t) = ls.translations {
        b.table_add_offset(6, t);
    }
    b.end_table()
}

fn build_log_entry(b: &mut FlatccBuilder, entry: &LogEntry, scripts: &[ScriptRow]) -> Ref {
    let name = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);

    let entry_contents: HashMap<i32, &str> = scripts
        .iter()
        .map(|s| (s.entry_id, s.content.as_str()))
        .collect();
    let content_ = entry_contents
        .get(&(entry.entry_id as i32)).copied().unwrap_or(&"");

    let content = b.create_string(content_);

    b.start_table(6);
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    b.table_add_u32(2, entry.awaiting_deletion, 0);
    b.table_add_offset(3, name);
    b.table_add_offset(4, author);
    b.table_add_offset(5, content);
    b.end_table()
}

fn build_log_entry_with_gap(b: &mut FlatccBuilder, entry: &LogEntry, gap: usize) -> Ref {
    let name = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);
    b.push_zeros(gap);
    b.start_table(5);
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    b.table_add_u32(2, entry.awaiting_deletion, 0);
    b.table_add_offset(3, name);
    b.table_add_offset(4, author);
    b.end_table()
}
