use crate::structs::detection::Detection;
use crate::structs::detection_logic::DetectionLogic;
use crate::structs::detection_metadata::DetectionMetadata;

/// The Condition struct is used to extrapolate data based on the condition as defined in the Sigma Specification
/// https://github.com/SigmaHQ/sigma/wiki/Specification#condition
/// The Condition struct contains all outcomes that a single condition can be, to then be stored as a Detection.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectionCondition {
    pub metadata: DetectionMetadata,
    pub is_negated: Option<bool>,
    pub operator: Option<Operator>,
    pub search_identifier: Option<String>,
    pub nested_detections: Option<Detection>,
    pub detection_logic: DetectionLogic,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operator {
    And,
    Or,
}

impl DetectionCondition {
    pub fn init() -> DetectionCondition {
        DetectionCondition {
            metadata: DetectionMetadata::init(),
            search_identifier: None,
            is_negated: None,
            nested_detections: None,
            operator: None,
            detection_logic: DetectionLogic::init(),
        }
    }

    pub fn new(
        metadata: DetectionMetadata,
        is_negated: Option<bool>,
        operator: Option<Operator>,
        search_identifier: Option<String>,
        nested_detections: Option<Detection>,
    ) -> Self {
        Self {
            metadata,
            search_identifier,
            is_negated,
            nested_detections,
            operator,
            detection_logic: DetectionLogic::init(),
        }
    }
}
