use nom::bytes::complete::tag;
use nom::sequence::delimited;
use nom::IResult;

use crate::structs::detection_condition::DetectionCondition;
use crate::structs::detection::Detection;
use crate::detection_parsers::condition::sub_parsers::parser;
use crate::detection_parsers::condition::parser_output::ParserOutput;
use crate::detection_parsers::condition::take_until_unbalanced::take_until_unbalanced;
use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

pub fn parens_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut condition = DetectionCondition::init(); // builds the conditions in the parentheses

    let (remaining, result) = parens(input)?;
    let mut remaining_condition = remaining;
    let mut resulting_condition = result;

    let mut search_identifiers = Vec::new();

    while !resulting_condition.is_empty() {
        match parser(resulting_condition) {
            Ok((remaining, parser_output)) => {
                resulting_condition = remaining;

                search_identifiers = [search_identifiers, parser_output.result.metadata.search_identifiers.clone()].concat();

                match parser_output.metadata.parser_type.clone() {
                    ParserTypes::Parens => {
                        condition = parser_output.result.clone();
                        detection.conditions = Some(vec![parser_output.result.clone()]);
                    }
                    ParserTypes::OneOfThem => {
                        println!("ONE_OF_THEM");
                    }
                    ParserTypes::AllOfThem => {
                        println!("ALL_OF_THEM");
                    }
                    ParserTypes::OneOf => {
                        println!("ONE_OF");
                    }
                    ParserTypes::AllOf => {
                        println!("ALL_OF");
                    }
                    ParserTypes::Not => {
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::And => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::Or => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::Pipe => {
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE");
                    }
                    ParserTypes::SearchIdentifier => {
                        detection.conditions = Some(vec![parser_output.result]);
                    }
                    _ => {
                        print!("I DONT KNOW YET, ERROR MAYBE???");
                    }
                }
            }
            Err(..) => {}
        }
    }

    let mut parser_result = format!("{}{}{}", "(", result.to_string(), ")");
    let metadata = DetectionMetadata {
        parser_type: ParserTypes::Parens,
        parser_result,
        search_identifiers,
    };

    let mut result_condition = DetectionCondition::init();
    result_condition.metadata = metadata;
    result_condition.nested_detections = Some(detection);

    Ok((
        remaining_condition,
        ParserOutput {
            result: result_condition,
        },
    ))
}

fn parens(input: &str) -> IResult<&str, &str> {
    delimited(tag("("), take_until_unbalanced('(', ')'), tag(")"))(input.trim())
}

#[cfg(test)]
mod tests {

    use crate::structs::detection_condition::Operator::And;
    use crate::structs::detection_condition::{DetectionCondition, Operator};
    use crate::structs::detection::Detection;
    use crate::detection_parsers::condition::parens_parser::{parens, parens_parser};
    use crate::detection_parsers::condition::parser_output::ParserOutput;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

    #[test]
    fn run_parse_for_nested_parens_condition() {
        let result = parens_parser("( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent");
        assert_eq!(result, Ok((" and not filter_scmevent", ParserOutput {
            result: DetectionCondition {
                metadata: DetectionMetadata {
                    parser_type: ParserTypes::Parens,
                    parser_result: "( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) )".to_string(),
                    search_identifiers: vec!["wmi_filter_to_consumer_binding".to_string(), "consumer_keywords".to_string(), "wmi_filter_registration".to_string()]
                },
                is_negated: None,
                operator: None,
                search_identifier: None,
                nested_detections: Some(Detection {
                    operator: Some(Operator::Or),
                    conditions: Some(vec![
                        DetectionCondition {
                            metadata: DetectionMetadata {
                                parser_type: ParserTypes::Parens,
                                parser_result: "(wmi_filter_to_consumer_binding and consumer_keywords)".to_string(),
                                search_identifiers: vec!["wmi_filter_to_consumer_binding".to_string(), "consumer_keywords".to_string()]
                            },
                            is_negated: None,
                            operator: None,
                            search_identifier: None,
                            nested_detections: Some(Detection {
                                operator: Some(Operator::And),
                                conditions: Some(vec![
                                    DetectionCondition {
                                        metadata: DetectionMetadata {
                                            parser_type: ParserTypes::SearchIdentifier,
                                            parser_result: "wmi_filter_to_consumer_binding".to_string(),
                                            search_identifiers: vec!["wmi_filter_to_consumer_binding".to_string()]
                                        },
                                        is_negated: None,
                                        operator: None,
                                        search_identifier: Some("wmi_filter_to_consumer_binding".to_string()),
                                        nested_detections: None,
                                        detection_logic: DetectionLogic::init()
                                    },
                                    DetectionCondition {
                                        metadata: DetectionMetadata {
                                            parser_type: ParserTypes::And,
                                            parser_result: "and consumer_keywords".to_string(),
                                            search_identifiers: vec!["consumer_keywords".to_string()]
                                        },
                                        is_negated: None,
                                        operator: Some(Operator::And),
                                        search_identifier: Some("consumer_keywords".to_string()),
                                        nested_detections: None,
                                        detection_logic: DetectionLogic::init()
                                    }
                                ])
                            }),
                            detection_logic: DetectionLogic::init()
                        },
                        DetectionCondition {
                            metadata: DetectionMetadata {
                                parser_type: ParserTypes::Or,
                                parser_result: "or (wmi_filter_registration)".to_string(),
                                search_identifiers: vec!["wmi_filter_registration".to_string()]
                            },
                            is_negated: None,
                            operator: Some(Operator::Or),
                            search_identifier: None,
                            nested_detections: Some(Detection {
                                operator: None,
                                conditions: Some(vec![
                                    DetectionCondition {
                                        metadata: DetectionMetadata {
                                            parser_type: ParserTypes::SearchIdentifier,
                                            parser_result: "wmi_filter_registration".to_string(),
                                            search_identifiers: vec!["wmi_filter_registration".to_string()]
                                        },
                                        is_negated: None,
                                        operator: None,
                                        search_identifier: Some("wmi_filter_registration".to_string()),
                                        nested_detections: None,
                                        detection_logic: DetectionLogic::init()
                                    }
                                ])
                            }),
                            detection_logic: DetectionLogic::init()
                        }
                    ])
                }),
                detection_logic: DetectionLogic::init()
            }
        })))
    }

    #[test]
    fn nested_parens_parser_condition() {
        let result = parens_parser("( selection or (not filter and selection1) ) and keywords");
        assert_eq!(
            result,
            Ok((
                " and keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Parens,
                            parser_result: "( selection or (not filter and selection1) )".to_string(),
                            search_identifiers: vec!["selection".to_string(), "filter".to_string(), "selection1".to_string()]
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
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
                                },
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::Or,
                                        parser_result: "or (not filter and selection1)".to_string(),
                                        search_identifiers: vec!["filter".to_string(), "selection1".to_string()]
                                    },
                                    is_negated: None,
                                    operator: Some(Operator::Or),
                                    search_identifier: None,
                                    nested_detections: Some(Detection {
                                        operator: Some(And),
                                        conditions: Some(vec![
                                            DetectionCondition {
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
                                            },
                                            DetectionCondition {
                                                metadata: DetectionMetadata {
                                                    parser_type: ParserTypes::And,
                                                    parser_result: "and selection1".to_string(),
                                                    search_identifiers: vec!["selection1".to_string()]
                                                },
                                                is_negated: None,
                                                operator: Some(And),
                                                search_identifier: Some("selection1".to_string()),
                                                nested_detections: None,
                                                detection_logic: DetectionLogic::init()
                                            }
                                        ])
                                    }),
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

    /// Only parentheses can be passed into this parser. For that reason, all inputs will start with
    /// (remaining: &str, result: &str), and the value inside of the parentheses will always be result.
    #[test]
    fn parens_parser_condition() {
        let result = parens_parser("(selection or not filter) and keywords");
        assert_eq!(
            result,
            Ok((
                " and keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Parens,
                            parser_result: "(selection or not filter)".to_string(),
                            search_identifiers: vec!["selection".to_string(), "filter".to_string()]
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::Or),
                            conditions: Some(vec![
                                DetectionCondition {
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
                                },
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::Or,
                                        parser_result: "or not filter".to_string(),
                                        search_identifiers: vec!["filter".to_string()]
                                    },
                                    is_negated: Some(true),
                                    operator: Some(Operator::Or),
                                    search_identifier: Some("filter".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init()
                                }
                            ])
                        }),
                        detection_logic: DetectionLogic::init()
                    }
                }
            ))
        )
    }

    #[test]
    fn parens_input() {
        let parser_result =
            parens("((filter1 and filter2) or keywords or events) and not selection");
        assert_eq!(
            parser_result,
            Ok((
                " and not selection",
                "(filter1 and filter2) or keywords or events"
            ))
        );

        let remaining_value = match parser_result {
            Ok((returned, remaining)) => remaining,
            Err(err) => "Error",
        };

        // Test the nested parentheses
        let nested_parser_result = parens(remaining_value);
        assert_eq!(
            nested_parser_result,
            Ok((" or keywords or events", "filter1 and filter2"))
        );

        let parser_result = parens(" keywords and not selection ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind(
                "keywords and not selection",
                Tag
            )))
        );
    }
}
