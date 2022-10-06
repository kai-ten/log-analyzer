use crate::condition_parsers::and_parser::and_parser;
use crate::condition_parsers::or_parser::or_parser;
use nom::branch::alt;
use nom::bytes::complete::{tag_no_case, take_until, take_while};
use nom::combinator::{rest, value};
use nom::IResult;

use crate::structs::detection_condition::{DetectionCondition, Metadata, Operator, ParserTypes};
use crate::condition_parsers::parser_output::ParserOutput;

pub fn search_identifiers_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let (_, result) = search_identifiers(input)?;
    let metadata = Metadata::new(ParserTypes::SearchIdentifier, String::from(result));

    let condition = DetectionCondition::new(metadata, None, None, Some(String::from(result)), None);

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
    use super::*;

    #[test]
    fn multiple_search_identifiers() {
        let result = search_identifiers_parser("Selection and not Filter");
        assert_eq!(
            result,
            Ok((
                " and not Filter",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "Selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
                    }
                }
            ))
        )
    }

    #[test]
    fn search_identifier_condition() {
        let result = search_identifiers_parser("Selection");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: String::from("Selection"),
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
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
                        metadata: Metadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: String::from(""),
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("".to_string()),
                        nested_detections: None
                    }
                }
            ))
        );
    }

    #[test]
    fn search_identifier_input() {
        let mid_condition_parser_result = search_identifiers(" Selection and not Filter ");
        assert_eq!(
            mid_condition_parser_result,
            Ok((" and not Filter", "Selection"))
        );

        let end_of_condition_parser_result = search_identifiers(" Events ");
        assert_eq!(end_of_condition_parser_result, Ok(("", "Events")));

        let empty_string_parser_result = search_identifiers("");
        assert_eq!(empty_string_parser_result, Ok(("", "")));

        let empty_string_parser_result = search_identifiers("    ");
        assert_eq!(empty_string_parser_result, Ok(("", "")));
    }
}
