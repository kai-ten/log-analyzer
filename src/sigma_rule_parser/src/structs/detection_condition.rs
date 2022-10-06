use crate::structs::detection::Detection;

/// The Condition struct is used to extrapolate data based on the condition as defined in the Sigma Specification
/// https://github.com/SigmaHQ/sigma/wiki/Specification#condition
/// The Condition struct contains all outcomes that a single condition can be, to then be stored as a Detection.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectionCondition {
    pub metadata: Metadata,
    pub is_negated: Option<bool>,
    pub operator: Option<Operator>,
    pub search_identifier: Option<String>,
    pub nested_detections: Option<Detection>,
    // pub detection_logic: Option<>
}

/// The Metadata struct helps return extra data that is useful for recursive parsing.
/// This is necessary, as the return tuple from the Nom parser is (&str, ParserOutput<Condition>),
///     where &str is the remaining condition string value to be parsed, and ParserOutput is the Condition struct.
///     returning parser_result allows us to perform nested Condition parsing by checking if that value is empty or contains a '('
#[derive(Clone, Debug, PartialEq)]
pub struct Metadata {
    pub parser_type: ParserTypes,
    pub parser_result: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParserTypes {
    Parens,
    OneOfThem,
    AllOfThem,
    OneOf,
    AllOf,
    Not,
    And,
    Or,
    Pipe,
    SearchIdentifier,
    Nunya,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operator {
    And,
    Or,
}

impl DetectionCondition {
    pub fn init() -> DetectionCondition {
        DetectionCondition {
            metadata: Metadata {
                parser_type: ParserTypes::Nunya,
                parser_result: String::from(""),
            },
            search_identifier: None,
            is_negated: None,
            nested_detections: None,
            operator: None,
        }
    }

    pub fn new(
        metadata: Metadata,
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
        }
    }
}

impl Metadata {
    pub fn new(parser_type: ParserTypes, parser_result: String) -> Self {
        Self {
            parser_type,
            parser_result,
        }
    }
}
