use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Translations {
    pub info: TranslationInfo,
    pub strings: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationInfo {
    pub name: String,
    pub full_name: String,
    pub loc_name: String,
}
