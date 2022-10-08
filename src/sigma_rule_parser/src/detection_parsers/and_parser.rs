use crate::detection_parsers::not_parser::not_parser;
use crate::detection_parsers::parens_parser::parens_parser;
use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;

use crate::structs::detection_condition::{DetectionCondition, Operator};
use crate::detection_parsers::parser_output::ParserOutput;
use crate::detection_parsers::search_id_parser::search_identifiers_parser;
use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

pub fn and_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let mut condition = DetectionCondition::init();

    let (remaining, result) = and(input)?;
    let mut result_condition: String = String::from(result);

    let and_parser_result = downstream_and_parser(remaining.trim());
    match and_parser_result {
        Ok((_, parser_output)) => {
            let downstream_parser_result = parser_output.metadata.parser_result.clone();
            result_condition = format!("{}{}{}", result_condition, " ", downstream_parser_result);

            let metadata = DetectionMetadata::new(ParserTypes::And, result_condition.clone());

            condition = DetectionCondition::new(
                metadata,
                parser_output.is_negated.clone(),
                Some(Operator::And),
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

pub fn and(input: &str) -> IResult<&str, &str> {
    tag_no_case("and")(input.trim())
}

fn downstream_and_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    alt((parens_parser, not_parser, search_identifiers_parser))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::detection::Detection;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::ParserTypes;

    #[test]
    fn and_parens_parser_condition_with_remaining() {
        let result = and_parser("and (filter or not selection) and keywords");
        assert_eq!(
            result,
            Ok((
                " and keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and (filter or not selection)".to_string(),
                        },
                        is_negated: None,
                        operator: Some(Operator::And),
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "filter".to_string()
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
                                        parser_result: "or not selection".to_string()
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
    fn and_parens_parser_condition() {
        let result = and_parser("and (filter or not selection)");
        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and (filter or not selection)".to_string(),
                        },
                        is_negated: None,
                        operator: Some(Operator::And),
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "filter".to_string()
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
                                        parser_result: "or not selection".to_string()
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
    fn and_not_parser_condition() {
        let result = and_parser("and not filter");

        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and not filter".to_string(),
                        },
                        is_negated: Some(true),
                        operator: Some(Operator::And),
                        search_identifier: Some("filter".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn and_parser_condition() {
        let result = and_parser("and filter");

        assert_eq!(
            result,
            Ok((
                "",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and filter".to_string(),
                        },
                        is_negated: None,
                        operator: Some(Operator::And),
                        search_identifier: Some("filter".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        );
    }

    #[test]
    fn and_parens_input() {
        let parser_result = and(" and (events or selection) ");
        assert_eq!(parser_result, Ok((" (events or selection)", "and")));
    }

    #[test]
    fn and_input() {
        let parser_result = and(" and events ");
        assert_eq!(parser_result, Ok((" events", "and")));

        let parser_result = and(" or events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("or events", Tag)))
        );
    }
}
