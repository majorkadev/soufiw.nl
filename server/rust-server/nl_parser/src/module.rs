use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::flatbuf::nl;
use crate::skin_data::SkinData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub version: u32,
    pub author: String,
    pub auth_token: String,
    pub checksum: u32,
    pub buffer_capacity: u32,
    pub enabled: u32,
    pub config_log: Vec<LogEntry>,
    pub script_log: Vec<LogEntry>,
    pub languages: Vec<Language>,
    pub skin_data: SkinData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub entry_id: u32,
    pub timestamp: u32,
    /// Display name (field 3). The entry type (Script/Config) is implicit
    /// from which vector (config_log vs script_log) the entry belongs to.
    pub name: String,
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Language {
    pub code: String,
    pub english_name: String,
    pub native_name: String,
    /// Raw JSON value preserving all original fields through round-trips.
    pub translations: Option<serde_json::Value>,
}

impl Module {
    /// Parse a decompressed FlatBuffer into an owned Module.
    ///
    /// Catches panics from the flatbuffers crate (which panics on malformed input)
    /// and converts them to errors.
    pub fn from_flatbuffer(data: &[u8]) -> Result<Self> {
        let data = data.to_vec(); // owned copy for catch_unwind (Send)
        match std::panic::catch_unwind(|| Self::from_flatbuffer_inner(&data)) {
            Ok(result) => result,
            Err(panic) => {
                let msg = if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "unknown panic".to_string()
                };
                Err(anyhow::anyhow!("flatbuffers panic: {msg}"))
            }
        }
    }

    fn from_flatbuffer_inner(data: &[u8]) -> Result<Self> {
        let wrapper = nl::root_as_module_wrapper(data)
            .map_err(|e| anyhow::anyhow!("invalid outer FlatBuffer: {e}"))?;

        let module_data = wrapper
            .payload_nested_flatbuffer()
            .context("missing payload (inner FlatBuffer)")?;

        let author = module_data
            .author()
            .unwrap_or_default()
            .to_string();
        let auth_token = module_data
            .auth_token()
            .unwrap_or_default()
            .to_string();

        let config_log = parse_log_vec(module_data.config_log());
        let script_log = parse_log_vec(module_data.script_log());
        let languages = parse_languages(module_data.languages())?;

        let skin_bytes = module_data
            .skin_data()
            .context("missing skin_data")?;
        let skin_data: SkinData =
            rmp_serde::from_slice(skin_bytes.bytes())
                .context("MsgPack skin_data deserialization")?;

        Ok(Module {
            version: wrapper.version(),
            author,
            auth_token,
            checksum: module_data.checksum(),
            buffer_capacity: module_data.buffer_capacity(),
            enabled: module_data.enabled(),
            config_log,
            script_log,
            languages,
            skin_data,
        })
    }

    /// Extract raw skin_data MsgPack bytes from decompressed FlatBuffer data
    /// without deserializing through Rust structs.
    pub fn extract_raw_skin_data(data: &[u8]) -> Result<Vec<u8>> {
        let wrapper = nl::root_as_module_wrapper(data)
            .map_err(|e| anyhow::anyhow!("invalid outer FlatBuffer: {e}"))?;
        let module_data = wrapper
            .payload_nested_flatbuffer()
            .context("missing payload (inner FlatBuffer)")?;
        let skin_bytes = module_data
            .skin_data()
            .context("missing skin_data")?;
        Ok(skin_bytes.bytes().to_vec())
    }

    /// Serialize this Module to decompressed FlatBuffer bytes.
    pub fn to_flatbuffer(&self) -> Result<Vec<u8>> {
        let inner_bytes = self.build_inner_flatbuffer()?;

        // Outer wrapper: force_defaults so version=0 is written explicitly,
        // and reverse field order so version is at higher table offset (matching original).
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        fbb.force_defaults(true);
        let payload = fbb.create_vector(&inner_bytes);
        let mut wrapper_builder = nl::ModuleWrapperBuilder::new(&mut fbb);
        wrapper_builder.add_version(self.version);
        wrapper_builder.add_payload(payload);
        let wrapper = wrapper_builder.finish();
        nl::finish_module_wrapper_buffer(&mut fbb, wrapper);
        Ok(fbb.finished_data().to_vec())
    }

    fn build_inner_flatbuffer(&self) -> Result<Vec<u8>> {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();

        // Serialize skin_data to MsgPack (named/map encoding, not positional/array)
        let skin_bytes =
            rmp_serde::to_vec_named(&self.skin_data).context("MsgPack skin_data serialization")?;
        let skin_data_vec = fbb.create_vector(&skin_bytes);

        // Empty extra_data vector
        let extra_data_vec = fbb.create_vector::<u8>(&[]);

        // Strings
        let author_str = fbb.create_string(&self.author);
        let auth_token_str = fbb.create_string(&self.auth_token);

        // Config log
        let config_log_offsets: Vec<_> = self
            .config_log
            .iter()
            .map(|e| build_log_entry(&mut fbb, e))
            .collect();
        let config_log_vec = fbb.create_vector(&config_log_offsets);

        // Script log
        let script_log_offsets: Vec<_> = self
            .script_log
            .iter()
            .map(|e| build_log_entry(&mut fbb, e))
            .collect();
        let script_log_vec = fbb.create_vector(&script_log_offsets);

        // Languages
        let language_offsets: Vec<_> = self
            .languages
            .iter()
            .map(|l| build_language(&mut fbb, l))
            .collect::<Result<Vec<_>>>()?;
        let languages_vec = fbb.create_vector(&language_offsets);

        // Manual field ordering matching original binary layout.
        // Fields pushed first get the highest table offset.
        // unknown_0 and unknown_10 are intentionally omitted (absent in original).
        let mut builder = nl::ModuleDataBuilder::new(&mut fbb);
        builder.add_config_log(config_log_vec);
        builder.add_script_log(script_log_vec);
        builder.add_languages(languages_vec);
        builder.add_extra_data(extra_data_vec);
        builder.add_author(author_str);
        builder.add_skin_data(skin_data_vec);
        builder.add_checksum(self.checksum);
        builder.add_enabled(self.enabled);
        builder.add_buffer_capacity(self.buffer_capacity);
        builder.add_auth_token(auth_token_str);
        let module_data = builder.finish();
        fbb.finish_minimal(module_data);
        Ok(fbb.finished_data().to_vec())
    }
}

fn build_log_entry<'a>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'a>,
    entry: &LogEntry,
) -> flatbuffers::WIPOffset<nl::LogEntry<'a>> {
    let name = fbb.create_string(&entry.name);
    let author = fbb.create_string(&entry.author);
    nl::LogEntry::create(
        fbb,
        &nl::LogEntryArgs {
            entry_id: entry.entry_id,
            timestamp: entry.timestamp,
            unknown_2: None,
            entry_type: Some(name),
            author: Some(author),
        },
    )
}

pub fn build_language<'a>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'a>,
    lang: &Language,
) -> Result<flatbuffers::WIPOffset<nl::Language<'a>>> {
    let code = fbb.create_string(&lang.code);
    let english_name = fbb.create_string(&lang.english_name);
    let native_name = fbb.create_string(&lang.native_name);

    let translations = match &lang.translations {
        Some(value) => {
            let json_bytes = serialize_translations_json(value)?;
            let json_str = std::str::from_utf8(&json_bytes)
                .context("translations JSON is not valid UTF-8")?;
            // Use create_string instead of create_vector to append a null terminator
            // in the FlatBuffer binary. The C++ client reads translations as a
            // null-terminated C string rather than using the vector length prefix.
            let str_offset = fbb.create_string(json_str);
            Some(flatbuffers::WIPOffset::new(str_offset.value()))
        }
        None => None,
    };

    Ok(nl::Language::create(
        fbb,
        &nl::LanguageArgs {
            unknown_0: None,
            unknown_1: None,
            code: Some(code),
            unknown_3: None,
            english_name: Some(english_name),
            native_name: Some(native_name),
            translations,
        },
    ))
}

/// Serialize translations JSON value with \r\n line endings and 4-space indent,
/// matching the original format.
pub fn serialize_translations_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    use serde::Serialize;
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value.serialize(&mut ser).context("JSON translation serialization")?;
    // Replace \n with \r\n
    let s = String::from_utf8(buf).context("JSON is not valid UTF-8")?;
    Ok(s.replace('\n', "\r\n").into_bytes())
}

fn parse_log_vec(
    vec: Option<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<nl::LogEntry<'_>>>>,
) -> Vec<LogEntry> {
    let Some(vec) = vec else { return Vec::new() };
    (0..vec.len())
        .map(|i| {
            let e = vec.get(i);
            LogEntry {
                entry_id: e.entry_id(),
                timestamp: e.timestamp(),
                name: e.entry_type().unwrap_or_default().to_string(),
                author: e.author().unwrap_or_default().to_string(),
            }
        })
        .collect()
}

fn parse_languages(
    vec: Option<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<nl::Language<'_>>>>,
) -> Result<Vec<Language>> {
    let Some(vec) = vec else { return Ok(Vec::new()) };
    (0..vec.len())
        .map(|i| {
            let l = vec.get(i);
            let translations = match l.translations() {
                Some(bytes) if !bytes.is_empty() => {
                    let value: serde_json::Value = serde_json::from_slice(bytes.bytes())
                        .with_context(|| {
                            format!(
                                "JSON parse failed for language '{}'",
                                l.code().unwrap_or("?")
                            )
                        })?;
                    Some(value)
                }
                _ => None,
            };
            Ok(Language {
                code: l.code().unwrap_or_default().to_string(),
                english_name: l.english_name().unwrap_or_default().to_string(),
                native_name: l.native_name().unwrap_or_default().to_string(),
                translations,
            })
        })
        .collect()
}
