use crate::detection_parsers::condition::and_parser::and_parser;
use crate::detection_parsers::condition::or_parser::or_parser;
use nom::branch::alt;
use nom::bytes::complete::{tag_no_case, take_until, take_while};
use nom::combinator::{rest, value};
use nom::IResult;

use crate::structs::detection_condition::{DetectionCondition, Operator};
use crate::detection_parsers::condition::parser_output::ParserOutput;
use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

pub fn search_identifiers_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let (_, result) = search_identifiers(input)?;
    let metadata = DetectionMetadata::new(
        ParserTypes::SearchIdentifier,
        String::from(result.clone()),
        vec![result.clone().to_string()],
    );

    let condition = DetectionCondition::new(
        metadata,
        None,
        None,
        Some(String::from(result)),
        None,

    );

    value(
        ParserOutput {
            result: { condition.clone() },
        },
        take_while(|ch| ch != ' '),
    )(input.trim())
}

/// Returns search identifiers within a condition (take_until(" ")), and at the end of a condition (rest of string)
/// Returns the remaining string to parse, the result that was parsed, and the condition being updated.
/// A successful response indicates that the condition is completed and ready to be stored in a Detection struct
/// A failure indicates invalid input, or potentially a missed parsing use-case.
fn search_identifiers(input: &str) -> IResult<&str, &str> {
    let sid = alt((take_until(" "), rest))(input.trim());

    let sid_result = match sid {
        Ok(parsed_sid) => parsed_sid,
        Err(e) => return Err(e),
    };

    Ok(sid_result)
}

#[cfg(test)]
mod tests {
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};
    use super::*;

    #[test]
    fn multiple_search_identifiers() {
        let result = search_identifiers_parser("selection and not filter");
        assert_eq!(
            result,
            Ok((
                " and not filter",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "selection".to_string(),
                            search_identifiers: vec!["selection".to_string()]
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("selection".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        )
    }

    #[test]
    fn search_identifier_condition() {
        let result = search_identifiers_parser("selection");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: String::from("selection"),
                            search_identifiers: vec!["selection".to_string()],
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("selection".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );

        let result = search_identifiers_parser("");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: String::from(""),
                            search_identifiers: vec!["".to_string()]
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn search_identifier_input() {
        let mid_condition_parser_result = search_identifiers(" selection and not filter ");
        assert_eq!(
            mid_condition_parser_result,
            Ok((" and not filter", "selection"))
        );

        let end_of_condition_parser_result = search_identifiers(" events ");
        assert_eq!(end_of_condition_parser_result, Ok(("", "events")));

        let empty_string_parser_result = search_identifiers("");
        assert_eq!(empty_string_parser_result, Ok(("", "")));

        let empty_string_parser_result = search_identifiers("    ");
        assert_eq!(empty_string_parser_result, Ok(("", "")));
    }
}
