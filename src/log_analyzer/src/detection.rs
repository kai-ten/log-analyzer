use anyhow::Error;
use log::info;
use sigma_rule_parser::parser::parse_detection_condition;
use sigma_rule_parser::sigma_file::sigma_rule::{DetectionTypes, SigmaRule};
use sigma_rule_parser::structs::detection_condition::{DetectionCondition, ParserTypes};
use sigma_rule_parser::structs::detection::Detection;
use sigma_rule_parser::condition_parsers::sub_parsers::parser;
use std::collections::BTreeMap;
use std::vec;

pub fn process_detection(sigma_rules: Vec<SigmaRule>) -> Result<(), Error> {

    let detection = Detection::init();

    for rule in sigma_rules {
        println!("RULE: {:?}", rule);
        let rule_id = rule.id;
        let detection = rule.detection;
        let detectionsss = detection.keys();
        println!("$$$$$${:?}", detectionsss); // ["condition", "filter", "selection", "selection1", "selection2"]

        println!("{:?}", detection);

        let condition = match process_condition(rule_id, detection) {
            Some(condition) => condition,
            None => {
                // TODO
                // skips to the next rule in the for loop, maybe return message here instead of in process_condition
                continue;
            }
        };

        let mut detection = Detection::init();

        // let mut remaining_condition = condition.as_str();
        // while remaining_condition.is_empty() {
        //     let ok = parse_condition(remaining_condition);
        //     let conditionz = match ok {
        //         Ok(wow) => {
        //             remaining_condition = wow.0;
        //             wow.1
        //         }
        //         Err(err) => {}
        //     };
        // }
    }

    Ok(())
}

fn process_condition(
    rule_id: String,
    detection: BTreeMap<String, DetectionTypes>,
) -> Option<String> {
    // TODO
    // Since an Option is being returned, I am unsure if None would trigger the else or not.
    // Must write test eventually and change to match if None doesn't trigger the else statement
    let condition_value = if detection.contains_key("condition") {
        let condition = detection.get("condition");
        let condition_value = read_condition(condition).to_string();

        if condition_value != "" {
            // maybe call parse_condition here and then return a Condition struct?
            Some(condition_value)
        } else {
            info!(
                "Condition returned as empty string, this rule has been skipped - {:?}",
                rule_id
            );
            None
        }
    } else {
        info!(
            "Detection must have a condition, this rule has been skipped - {:?}",
            rule_id
        );
        None
    };

    condition_value
}

/// Parses a single condition for a detection
pub fn parse_detection(rule_condition: &str) -> Result<Detection, Error> {
    let mut detection = Detection::init();
    detection = parse_detection_condition(rule_condition).unwrap();   // rename to parse_detection_condition()
                                                                            // create method parse_detection_logic
                                                                            // detection.condition_logic = parse_detection_condition();
                                                                            // returns current Condition struct
                                                                            // detection.detection_logic = parse_detection_logic();
                                                                            // returns the logic
                                                                            // return the whole Detection

    Ok(detection)
}

/// Conditions are returned by the yml processor as the Enum DetectionTypes.
/// This method extracts the type that the value is stored in and stringifies the value.
fn read_condition(condition: Option<&DetectionTypes>) -> &str {
    let condition_value = match condition.unwrap() {
        DetectionTypes::Boolean(condition) => stringify!(condition),
        DetectionTypes::Number(condition) => stringify!(condition),
        DetectionTypes::String(condition) => condition as &str,
        //TODO - Sequence should be supported as defined in the spec, a list of conditions joins as OR conditionals
        DetectionTypes::Sequence(_) => "",
        DetectionTypes::Mapping(_) => "",
    };

    condition_value
}

fn initialize_parser(parsed_result: &str) {
    if parsed_result.len() > 1 {}
}

mod tests {
    use sigma_rule_parser::parser::parse_detection_condition;
    use sigma_rule_parser::structs::detection_condition::{DetectionCondition, Metadata, Operator, ParserTypes};
    use sigma_rule_parser::structs::detection::Detection;

    #[test]
    fn run_parse_for_nested_parens_condition() {
        let result = parse_detection_condition("( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent");
        assert_eq!(result, Ok(Detection {
            operator: Some(Operator::And),
            conditions: Some(vec![
                DetectionCondition {
                    metadata: Metadata {
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
                                metadata: Metadata {
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
                                            metadata: Metadata {
                                                parser_type: ParserTypes::SearchIdentifier,
                                                parser_result: "wmi_filter_to_consumer_binding".to_string()
                                            },
                                            is_negated: None,
                                            operator: None,
                                            search_identifier: Some("wmi_filter_to_consumer_binding".to_string()),
                                            nested_detections: None
                                        },
                                        DetectionCondition {
                                            metadata: Metadata {
                                                parser_type: ParserTypes::And,
                                                parser_result: "and consumer_keywords".to_string()
                                            },
                                            is_negated: None,
                                            operator: Some(Operator::And),
                                            search_identifier: Some("consumer_keywords".to_string()),
                                            nested_detections: None
                                        }
                                    ])
                                })
                            },
                            DetectionCondition {
                                metadata: Metadata {
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
                                            metadata: Metadata {
                                                parser_type: ParserTypes::SearchIdentifier,
                                                parser_result: "wmi_filter_registration".to_string()
                                            },
                                            is_negated: None,
                                            operator: None,
                                            search_identifier: Some("wmi_filter_registration".to_string()),
                                            nested_detections: None
                                        }
                                    ])
                                })
                            }
                        ])
                    })
                },
                DetectionCondition {
                    metadata: Metadata {
                        parser_type: ParserTypes::And,
                        parser_result: "and not filter_scmevent".to_string()
                    },
                    is_negated: Some(true),
                    operator: Some(Operator::And),
                    search_identifier: Some("filter_scmevent".to_string()),
                    nested_detections: None
                }
            ])
        }))
    }

    #[test]
    fn run_parse_for_parens_condition() {
        let result =
            parse_detection_condition("Not Keywords or (Selection and not Filter) or Selection1");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::Or),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::Not,
                            parser_result: "Not Keywords".to_string()
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: Some("Keywords".to_string()),
                        nested_detections: None
                    },
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or (Selection and not Filter)".to_string()
                        },
                        is_negated: None,
                        operator: Some(Operator::Or),
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(Operator::And),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: ParserTypes::SearchIdentifier,
                                        parser_result: "Selection".to_string()
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("Selection".to_string()),
                                    nested_detections: None
                                },
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: ParserTypes::And,
                                        parser_result: "and not Filter".to_string()
                                    },
                                    is_negated: Some(true),
                                    operator: Some(Operator::And),
                                    search_identifier: Some("Filter".to_string()),
                                    nested_detections: None
                                }
                            ])
                        })
                    },
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or Selection1".to_string()
                        },
                        is_negated: None,
                        operator: Some(Operator::Or),
                        search_identifier: Some("Selection1".to_string()),
                        nested_detections: None
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_or_not() {
        let result = parse_detection_condition("Selection or not Filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::Or),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "Selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
                    },
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::Or,
                            parser_result: "or not Filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(Operator::Or),
                        search_identifier: Some("Filter".to_string()),
                        nested_detections: None
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_and_not() {
        let result = parse_detection_condition("Selection and not Filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(Operator::And),
                conditions: Some(vec![
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::SearchIdentifier,
                            parser_result: "Selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
                    },
                    DetectionCondition {
                        metadata: Metadata {
                            parser_type: ParserTypes::And,
                            parser_result: "and not Filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(Operator::And),
                        search_identifier: Some("Filter".to_string()),
                        nested_detections: None
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
                    metadata: Metadata {
                        parser_type: ParserTypes::SearchIdentifier,
                        parser_result: "Selection".to_string()
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("Selection".to_string()),
                    nested_detections: None
                }])
            })
        )
    }
}
