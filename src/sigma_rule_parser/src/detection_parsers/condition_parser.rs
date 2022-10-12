use std::fmt;
use std::fmt::Error;
use log::{error, info};
use crate::detection_parsers::sub_parsers::parser;
use crate::structs::detection::Detection;
use crate::structs::detection_metadata::ParserTypes;

/// This function is responsible for handling each Sigma rule condition that is passed to it, returning a Detection.
/// These Detections should be collected into a vec<> for further processing of the Detection Logic.
///
/// At a high level, this method compares the search identifiers in the detection field to the search identifiers found in the condition field
///     of a Sigma rule.
pub fn parse_detection_condition(condition: &str, search_identifiers: Vec<String>) -> Result<Detection, Error> {
    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut remaining_condition = condition;

    let mut search_identifiers_result = Vec::new();

    while !remaining_condition.is_empty() {
        match parser(remaining_condition) {
            Ok((remaining, parser_output)) => {
                remaining_condition = remaining;

                search_identifiers_result = parser_output.metadata.search_identifiers.clone();

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

    match validate_conditions(search_identifiers, search_identifiers_result) {
        true => Ok(detection),
        false => Err(Error)
    }
}

/// This function compares all of the conditions that were found in the "condition: ..." field of the Sigma rule.
/// If all conditions in the parsing of the condition are found, then that means the rule may have valid detection logic.
/// If not all conditions in the parsing of the condition are NOT found, then the rule is invalid because the condition uses a rule that the file does not define.
fn validate_conditions(search_identifiers: Vec<String>, search_identifiers_result: Vec<String>) -> bool {
    let matching = search_identifiers_result.clone().iter().zip(&search_identifiers).filter(|&(a, b)| a == b).count();

    return if search_identifiers_result.len() == matching {
        true
    } else {
        false
    }
}


#[cfg(test)]
mod tests {
    use crate::detection_parsers::condition_parser::{parse_detection_condition, validate_conditions};
    use crate::structs::detection::Detection;
    use crate::structs::detection_condition::{DetectionCondition, Operator};
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};

    #[test]
    fn parse_search_identifier_that_does_not_exist() {
        let search_identifiers: Vec<String> = vec!["selection".to_string(), "filter".to_string()];
        let result = parse_detection_condition("keywords and not filter", search_identifiers);
        println!("result = {:?}", result);
    }

    #[test]
    fn run_parse_for_nested_parens_condition() {
        let search_identifiers: Vec<String> = vec!["filter_scmevent".to_string()];
        let result = parse_detection_condition("( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent", search_identifiers);
        assert_eq!(result, Ok(Detection {
            operator: Some(Operator::And),
            conditions: Some(vec![
                DetectionCondition {
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
                                            detection_logic: DetectionLogic::init(),
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
                                            detection_logic: DetectionLogic::init(),
                                        }
                                    ])
                                }),
                                detection_logic: DetectionLogic::init(),
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
                        parser_result: "and not filter_scmevent".to_string(),
                        search_identifiers: vec!["filter_scmevent".to_string()]
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
        let search_identifiers: Vec<String> = vec!["selection1".to_string()];
        let result = parse_detection_condition("not keywords or (selection and not filter) or selection1", search_identifiers);
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::Or),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "not keywords".to_string(),
                            search_identifiers: vec!["keywords".to_string()]
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
                            parser_result: "or (selection and not filter)".to_string(),
                            search_identifiers: vec!["selection".to_string(), "filter".to_string()]
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
                                        parser_result: "selection".to_string(),
                                        search_identifiers: vec!["selection".to_string()]
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
                                        parser_result: "and not filter".to_string(),
                                        search_identifiers: vec!["filter".to_string()]
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
                            parser_result: "or selection1".to_string(),
                            search_identifiers: vec!["selection1".to_string()]
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
        let search_identifiers: Vec<String> = vec!["filter".to_string()];
        let result = parse_detection_condition("selection or not filter", search_identifiers);

        assert_eq!(
            result,
            Ok(Detection {
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
                        detection_logic: DetectionLogic::init(),
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
                        detection_logic: DetectionLogic::init(),
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_and_not() {
        let search_identifiers: Vec<String> = vec!["filter".to_string()];
        let result = parse_detection_condition("selection and not filter", search_identifiers);
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::And),
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
                        detection_logic: DetectionLogic::init(),
                    },
                    DetectionCondition {
                        metadata: DetectionMetadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and not filter".to_string(),
                            search_identifiers: vec!["filter".to_string()]
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
        let search_identifiers: Vec<String> = vec!["selection".to_string()];
        let result = parse_detection_condition("selection", search_identifiers);
        assert_eq!(
            result,
            Ok(Detection {
                operator: None,
                conditions: Some(vec![DetectionCondition {
                    metadata: DetectionMetadata {
                        parser_type: ParserTypes::SearchIdentifier,
                        parser_result: "selection".to_string(),
                        search_identifiers: vec!["selection".to_string()]
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("selection".to_string()),
                    nested_detections: None,
                    detection_logic: DetectionLogic::init(),
                }])
            })
        )
    }

    #[test]
    fn valid_conditions_were_found() {
        let search_identifiers = vec!["selection".to_string(), "filter".to_string()];
        let search_identifiers_result = vec!["selection".to_string(), "filter".to_string()];

        let is_valid = validate_conditions(search_identifiers, search_identifiers_result);
        assert_eq!(is_valid, true);
    }

    #[test]
    fn valid_conditions_not_found() {
        let search_identifiers = vec!["selection".to_string(), "filter".to_string()];
        let search_identifiers_result = vec!["keywords".to_string(), "filter".to_string()];

        let is_valid = validate_conditions(search_identifiers, search_identifiers_result);
        assert_eq!(is_valid, false);
    }
}
