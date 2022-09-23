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
    pub fn new() -> Detection {
        Detection {
            operator: None,
            conditions: None,
        }
    }

    // fn modify(&mut self) -> Detection {
    //     Detection {
    //         search_identifier,
    //         negation,
    //         nested_detections
    //     }
    // }
}