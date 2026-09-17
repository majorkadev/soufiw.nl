use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize null/nil as T::default() (empty Vec, empty IndexMap, etc.)
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkinData {
    pub skins: Skins,
    #[serde(deserialize_with = "null_as_default")]
    pub radio: IndexMap<String, IndexMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skins {
    #[serde(deserialize_with = "null_as_default")]
    pub paintkits: IndexMap<String, Vec<PaintKit>>,
    #[serde(deserialize_with = "null_as_default")]
    pub weapons: IndexMap<String, Weapon>,
    #[serde(deserialize_with = "null_as_default")]
    pub stickers: IndexMap<String, StickerCollection>,
    #[serde(deserialize_with = "null_as_default")]
    pub custom_players: IndexMap<String, CustomPlayer>,
    #[serde(deserialize_with = "null_as_default")]
    pub patches: IndexMap<String, PatchCollection>,
    #[serde(deserialize_with = "null_as_default")]
    pub music_kits: Vec<MusicKit>,
    #[serde(deserialize_with = "null_as_default")]
    pub coins: IndexMap<String, Coin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaintKit {
    pub id: i64,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub rarity: i64,
    #[serde(default)]
    pub tech_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weapon {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub is_fake_item: bool,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub sub_position: i64,
    #[serde(default)]
    pub tech_name: String,
    #[serde(rename = "type", default)]
    pub weapon_type: i64,
    #[serde(deserialize_with = "null_as_default")]
    pub used_by_classes: IndexMap<String, i64>,
    #[serde(default)]
    pub viewmodel: String,
    #[serde(default)]
    pub worldmodel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerCollection {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(deserialize_with = "null_as_default")]
    pub loot: Vec<StickerItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerItem {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub rarity: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPlayer {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub rarity: i64,
    #[serde(deserialize_with = "null_as_default")]
    pub used_by_classes: IndexMap<String, i64>,
    #[serde(default)]
    pub vo_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchCollection {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(deserialize_with = "null_as_default")]
    pub loot: Vec<PatchItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchItem {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub rarity: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MusicKit {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub tech_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub localized_name: String,
    #[serde(default)]
    pub rarity: i64,
}
