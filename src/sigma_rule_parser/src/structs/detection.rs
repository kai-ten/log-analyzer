use crate::structs::condition::{Condition, OPERATOR};

/// Contains the detections for all rules.
/// This struct is compared to incoming logs to determine if there is a match or not.
// #[derive(Clone, Debug, PartialEq)]
// struct Detections {
//     detections: Vec<Detection>,
// }

/// Contains the conditions for a single Detection.
// TODO - Conditions should not be Optional?
#[derive(Clone, Debug, PartialEq)]
pub struct Detection {
    pub operator: Option<OPERATOR>,
    pub conditions: Option<Vec<Condition>>,
}

impl Detection {
    pub fn init() -> Detection {
        Detection {
            operator: None,
            conditions: None,
        }
    }
}



// detection_logic: DetectionLogic {
//     fieldName: "TargetImage", // map to field mappings
//     fieldMappingName: "$.Event.Data.EventData.TargetImage", // this gets processed on initialization
//     modifier: None,
//     values: Map, Vec, String
// }
