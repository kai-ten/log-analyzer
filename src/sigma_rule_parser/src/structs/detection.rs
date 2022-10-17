use crate::structs::detection_condition::{DetectionCondition, Operator};


/// Contains the conditions for a single Detection.
// TODO: - Conditions should not be Optional?
#[derive(Clone, Debug, PartialEq)]
pub struct Detection {
    pub operator: Option<Operator>,
    pub conditions: Option<Vec<DetectionCondition>>,
}

impl Detection {
    pub fn init() -> Detection {
        Detection {
            operator: None,
            conditions: None,
        }
    }
}
