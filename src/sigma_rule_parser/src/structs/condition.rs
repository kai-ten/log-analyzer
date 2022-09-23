use crate::structs::detection::Detection;

/// Metadata and Fields to compose a Condition.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub parser_type: Option<PARSER_TYPES>,
    pub parser_result: Option<Vec<String>>,
    pub is_negated: Option<bool>,
    pub operator: Option<OPERATOR>,
    pub search_identifier: Option<String>,
    pub nested_detections: Option<Detection>,
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