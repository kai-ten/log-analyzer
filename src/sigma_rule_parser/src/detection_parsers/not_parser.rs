use crate::detection_parsers::parens_parser::parens_parser;
use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;

use crate::structs::detection_condition::DetectionCondition;
use crate::detection_parsers::parser_output::ParserOutput;
use crate::detection_parsers::search_id_parser::search_identifiers_parser;
use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

pub fn not_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let mut condition = DetectionCondition::init();

    let (remaining, result) = not(input)?;
    let mut result_condition: String = String::from(result);

    let not_parser_result = downstream_not_parser(remaining);
    match not_parser_result {
        Ok((_, parser_output)) => {
            let downstream_parser_result = parser_output.metadata.parser_result.clone();
            result_condition = format!("{}{}{}", result_condition, " ", downstream_parser_result);

            let metadata = DetectionMetadata::new(
                ParserTypes::Not,
                result_condition.clone(),
                parser_output.metadata.search_identifiers.clone(),
            );

            condition = DetectionCondition::new(
                metadata,
                Some(true),
                None,
                parser_output.search_identifier.clone(),
                parser_output.nested_detections.clone(),
            );
        }
        Err(_) => {}
    }

    value(
        ParserOutput {
            result: { condition.clone() },
        },
        tag_no_case(result_condition.clone().as_str()),
    )(input.trim())
}

fn not(input: &str) -> IResult<&str, &str> {
    tag_no_case("not")(input.trim())
}

fn downstream_not_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let result = alt((
        parens_parser,
        // one of / all of combos
        search_identifiers_parser,
    ))(input);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::detection_condition::Operator;
    use crate::structs::detection::Detection;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

    #[test]
    fn not_parens_parser_condition_with_remaining() {
        let result = not_parser("not (filter or not selection) or keywords");
        assert_eq!(
            result,
            Ok((
                " or keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "not (filter or not selection)".to_string(),
                            search_identifiers: vec!["filter".to_string(), "selection".to_string()]
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "filter".to_string(),
                                        search_identifiers: vec!["filter".to_string()]
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("filter".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init()
                                },
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::Or,
                                        parser_result: "or not selection".to_string(),
                                        search_identifiers: vec!["selection".to_string()]
                                    },
                                    is_negated: Some(true),
                                    operator: Some(Operator::Or),
                                    search_identifier: Some("selection".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init()
                                }
                            ])
                        }),
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn not_parens_parser_condition() {
        let result = not_parser("not (filter or not selection)");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "not (filter or not selection)".to_string(),
                            search_identifiers: vec!["filter".to_string(), "selection".to_string()]
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "filter".to_string(),
                                        search_identifiers: vec!["filter".to_string()]
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("filter".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init()
                                },
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::Or,
                                        parser_result: "or not selection".to_string(),
                                        search_identifiers: vec!["selection".to_string()]
                                    },
                                    is_negated: Some(true),
                                    operator: Some(Operator::Or),
                                    search_identifier: Some("selection".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init()
                                }
                            ])
                        }),
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn not_parser_condition() {
        let result = not_parser("not filter");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "not filter".to_string(),
                            search_identifiers: vec!["filter".to_string()]
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: Some("filter".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn not_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }
}
