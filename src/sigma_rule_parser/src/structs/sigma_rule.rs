use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// Next Steps:
// Add DetectionLogic to DetectionCondition
// For each condition, parse the logic and store
// What would it take to handle the logic for endswith / startswith / contains / etc

#[derive(Default, Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(default)] // deny_unknown_fields in the future? currently unable to parse custom fields defined by individuals
pub struct SigmaRule {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub modified: String,
    #[serde(default)]
    pub logsource: Logsource,
    #[serde(default)]
    pub related: Vec<YmlTypes>,
    #[serde(default)]
    pub detection: BTreeMap<String, YmlTypes>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
    #[serde(default)]
    pub level: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Logsource {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub definition: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(untagged)]
pub enum YmlTypes {
    Boolean(bool),
    Number(u64),
    String(String),
    Sequence(Vec<YmlTypes>),
    Mapping(Option<BTreeMap<String, YmlTypes>>),
}