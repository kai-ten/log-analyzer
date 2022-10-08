use std::fmt::Error;
use crate::detection_parsers::sub_parsers::parser;
use crate::structs::detection::Detection;
use crate::structs::detection_metadata::ParserTypes;

/// This function is responsible for handling each Sigma rule condition that is passed to it, returning a Detection.
/// These Detections should be collected into a vec<> for further processing of the Detection Logic.
pub fn parse_detection_condition(input: &str) -> Result<Detection, Error> {
    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut remaining_condition = input;

    while !remaining_condition.is_empty() {
        match parser(remaining_condition) {
            Ok((remaining, parser_output)) => {
                remaining_condition = remaining;

                match parser_output.metadata.parser_type.clone() {
                    ParserTypes::Parens => {
                        let condition = parser_output.result.clone();
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
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::And => {
                        detection.operator = parser_output.operator.clone();
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::Or => {
                        // TODO
                        // add check to see if detection.operator is None, OR, or AND.
                        // When it is an operator that does not equal another operator, this must create a nested condition
                        detection.operator = parser_output.operator.clone();
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    ParserTypes::Pipe => {
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE, Correlations not yet supported");
                    }
                    ParserTypes::SearchIdentifier => {
                        // create detection logic here
                        // let mut condition = parser_output.result;
                        // condition.detection_logic = parse_detection_logic();
                        println!("SID: {:?}", parser_output.result);
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

    Ok(detection)
}

#[cfg(test)]
mod tests {
    use crate::detection_parsers::condition_parser::parse_detection_condition;
    use crate::structs::detection::Detection;
    use crate::structs::detection_condition::{DetectionCondition, Operator};
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

    #[test]
    fn run_parse_for_nested_parens_condition() {
        let result = parse_detection_condition("( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent");
        assert_eq!(result, Ok(Detection {
            operator: Some(Operator::And),
            conditions: Some(vec![
                DetectionCondition {
                    metadata: DetectionMetadata {
                        parser_type: ParserTypes::Parens,
                        parser_result: "( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) )".to_string()
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
                                    parser_result: "(wmi_filter_to_consumer_binding and consumer_keywords)".to_string()
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
                                                parser_result: "wmi_filter_to_consumer_binding".to_string()
                                            },
                                            is_negated: None,
                                            operator: None,
                                            search_identifier: Some("wmi_filter_to_consumer_binding".to_string()),
                                            nested_detections: None,
                                            detection_logic: DetectionLogic::init(),
                                        },
                                        DetectionCondition {
                                            metadata: DetectionMetadata {
                                                parser_type: ParserTypes::And,
                                                parser_result: "and consumer_keywords".to_string()
                                            },
                                            is_negated: None,
                                            operator: Some(Operator::And),
                                            search_identifier: Some("consumer_keywords".to_string()),
                                            nested_detections: None,
                                            detection_logic: DetectionLogic::init(),
                                        }
                                    ])
                                }),
                                detection_logic: DetectionLogic::init(),
                            },
                            DetectionCondition {
                                metadata: DetectionMetadata {
                                    parser_type: ParserTypes::Or,
                                    parser_result: "or (wmi_filter_registration)".to_string()
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
                                                parser_result: "wmi_filter_registration".to_string()
                                            },
                                            is_negated: None,
                                            operator: None,
                                            search_identifier: Some("wmi_filter_registration".to_string()),
                                            nested_detections: None,
                                            detection_logic: DetectionLogic::init(),
                                        }
                                    ])
                                }),
                                detection_logic: DetectionLogic::init(),
                            }
                        ])
                    }),
                    detection_logic: DetectionLogic::init(),
                },
                DetectionCondition {
                    metadata: DetectionMetadata {
                        parser_type: ParserTypes::And,
                        parser_result: "and not filter_scmevent".to_string()
                    },
                    is_negated: Some(true),
                    operator: Some(Operator::And),
                    search_identifier: Some("filter_scmevent".to_string()),
                    nested_detections: None,
                    detection_logic: DetectionLogic::init(),
                }
            ])
        }))
    }

    #[test]
    fn run_parse_for_parens_condition() {
        let result = parse_detection_condition("not keywords or (selection and not filter) or selection1");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::Or),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "not keywords".to_string()
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: Some("keywords".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    },
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or (selection and not filter)".to_string()
                        },
                        is_negated: None,
                        operator: Some(Operator::Or),
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::And),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "selection".to_string()
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("selection".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init(),
                                },
                                DetectionCondition {
                                    metadata: DetectionMetadata {
                                        parser_type: ParserTypes::And,
                                        parser_result: "and not filter".to_string()
                                    },
                                    is_negated: Some(true),
                                    operator: Some(Operator::And),
                                    search_identifier: Some("filter".to_string()),
                                    nested_detections: None,
                                    detection_logic: DetectionLogic::init(),
                                }
                            ])
                        }),
                        detection_logic: DetectionLogic::init(),
                    },
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or selection1".to_string()
                        },
                        is_negated: None,
                        operator: Some(Operator::Or),
                        search_identifier: Some("selection1".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_or_not() {
        let result = parse_detection_condition("selection or not filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::Or),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("selection".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    },
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or not filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(Operator::Or),
                        search_identifier: Some("filter".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_and_not() {
        let result = parse_detection_condition("selection and not filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::And),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("selection".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    },
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and not filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(Operator::And),
                        search_identifier: Some("filter".to_string()),
                        nested_detections: None,
                        detection_logic: DetectionLogic::init(),
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_search_id() {
        let result = parse_detection_condition("Selection");
        assert_eq!(
            result,
            Ok(Detection {
                operator: None,
                conditions: Some(vec![DetectionCondition {
                    metadata: DetectionMetadata {
                        parser_type: ParserTypes::SearchIdentifier,
                        parser_result: "Selection".to_string()
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("Selection".to_string()),
                    nested_detections: None,
                    detection_logic: DetectionLogic::init(),
                }])
            })
        )
    }
}
