use std::collections::BTreeMap;

/// The name of the field corresponds to the logic that will take place when comparing a Detection to a Log.
/// The key for "and" and "key_value" fields is used to compare the Detection to the Field Mappings, and the Log to the Field Mappings.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectionLogic {
    pub and: Option<BTreeMap<String, DetectionLogic>>,
    pub or: Option<Vec<DetectionLogic>>,
    pub key_value: Option<(String, String)>,
    pub value: Option<String>,
}

impl DetectionLogic {
    pub fn init() -> DetectionLogic {
        DetectionLogic {
            and: None,
            or: None,
            key_value: None,
            value: None,
        }
    }
}
