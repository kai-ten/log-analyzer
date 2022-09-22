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
    pub(crate) operator: Option<OPERATOR>,
    pub(crate) conditions: Option<Vec<Condition>>,
}

/// Metadata and Fields to compose a Condition.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub(crate) parser_type: Option<PARSER_TYPES>,
    pub(crate) parser_result: Option<Vec<String>>,
    pub(crate) is_negated: Option<bool>,
    pub(crate) operator: Option<OPERATOR>,
    pub(crate) search_identifier: Option<String>,
    pub(crate) nested_detections: Option<Detection>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PARSER_TYPES {
    PARENS,
    ONE_OF_THEM,
    ALL_OF_THEM,
    ONE_OF,
    ALL_OF,
    NOT,
    AND,
    OR,
    PIPE,
    SEARCH_IDENTIFIER,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OPERATOR {
    AND,
    OR,
}

impl OPERATOR {
    fn as_str(&self) -> &'static str {
        match self {
            OPERATOR::AND => "and",
            OPERATOR::OR => "or"
        }
    }
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

impl Condition {
    pub fn new() -> Condition {
        Condition {
            parser_type: None,
            parser_result: None,
            search_identifier: None,
            is_negated: None,
            nested_detections: None,
            operator: None,
        }
    }

    // fn update(condition: &mut Condition) -> Condition {
    //     condition.search_identifier =
    // }

    // fn modify(&mut self) -> Detection {
    //     Detection {
    //         search_identifier,
    //         negation,
    //         nested_detections
    //     }
    // }
}