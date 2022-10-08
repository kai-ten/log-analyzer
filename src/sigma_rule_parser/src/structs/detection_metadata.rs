/// The Metadata struct helps return extra data that is useful for recursive parsing.
/// This is necessary, as the return tuple from the Nom parser is (&str, ParserOutput<Condition>),
///     where &str is the remaining condition string value to be parsed, and ParserOutput is the Condition struct.
///     returning parser_result allows us to perform nested Condition parsing by checking if that value is empty or contains a '('
#[derive(Clone, Debug, PartialEq)]
pub struct DetectionMetadata {
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

impl DetectionMetadata {
    pub fn init() -> DetectionMetadata {
        DetectionMetadata {
            parser_type: ParserTypes::Nunya,
            parser_result: String::from(""),
        }
    }

    pub fn new(parser_type: ParserTypes, parser_result: String) -> Self {
        Self {
            parser_type,
            parser_result,
        }
    }
}
