use crate::structs::condition::{Condition, PARSER_TYPES};
use crate::structs::detection::Detection;
use crate::sub_parsers::operator_parsers::parser;
use std::fmt::Error;

/// This function is responsible for handling each Sigma rule condition that is passed to it, returning a Detection.
/// These Detections should be collected into a vec<> for further processing of the Detection Logic.
pub fn parse(input: &str) -> Result<Detection, Error> {
    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut remaining_condition = input.clone();

    while !remaining_condition.is_empty() {
        match parser(remaining_condition) {
            Ok((remaining, parser_output)) => {
                remaining_condition = remaining;

                match parser_output.metadata.parser_type.clone() {
                    PARSER_TYPES::PARENS => {
                        let condition = parser_output.result.clone();
                        detection.conditions = Some(vec![parser_output.result.clone()]);
                    }
                    PARSER_TYPES::ONE_OF_THEM => {
                        println!("ONE_OF_THEM");
                    }
                    PARSER_TYPES::ALL_OF_THEM => {
                        println!("ALL_OF_THEM");
                    }
                    PARSER_TYPES::ONE_OF => {
                        println!("ONE_OF");
                    }
                    PARSER_TYPES::ALL_OF => {
                        println!("ALL_OF");
                    }
                    PARSER_TYPES::NOT => {
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::AND => {
                        detection.operator = parser_output.operator.clone();
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::OR => {
                        // TODO
                        // add check to see if detection.operator is None, OR, or AND.
                        // When it is an operator that does not equal another operator, this must create a nested condition
                        detection.operator = parser_output.operator.clone();
                        let condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::PIPE => {
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE");
                    }
                    PARSER_TYPES::SEARCH_IDENTIFIER => {
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

/// These tests are real scenarios of conditions that have been written in Sigma rules.
#[cfg(test)]
mod tests {
    use crate::parser::parse;
    use crate::structs::condition::{Condition, Metadata, OPERATOR, PARSER_TYPES};
    use crate::structs::detection::Detection;

    #[test]
    fn run_parse_for_nested_parens_condition() {
        let result = parse("( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent");
        assert_eq!(result, Ok(Detection {
            operator: Some(OPERATOR::AND),
            conditions: Some(vec![
                Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::PARENS,
                        parser_result: "( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) )".to_string()
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: None,
                    nested_detections: Some(Detection {
                        operator: Some(OPERATOR::OR),
                        conditions: Some(vec![
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::PARENS,
                                    parser_result: "(wmi_filter_to_consumer_binding and consumer_keywords)".to_string()
                                },
                                is_negated: None,
                                operator: None,
                                search_identifier: None,
                                nested_detections: Some(Detection {
                                    operator: Some(OPERATOR::AND),
                                    conditions: Some(vec![
                                        Condition {
                                            metadata: Metadata {
                                                parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                                                parser_result: "wmi_filter_to_consumer_binding".to_string()
                                            },
                                            is_negated: None,
                                            operator: None,
                                            search_identifier: Some("wmi_filter_to_consumer_binding".to_string()),
                                            nested_detections: None
                                        },
                                        Condition {
                                            metadata: Metadata {
                                                parser_type: PARSER_TYPES::AND,
                                                parser_result: "and consumer_keywords".to_string()
                                            },
                                            is_negated: None,
                                            operator: Some(OPERATOR::AND),
                                            search_identifier: Some("consumer_keywords".to_string()),
                                            nested_detections: None
                                        }
                                    ])
                                })
                            },
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::OR,
                                    parser_result: "or (wmi_filter_registration)".to_string()
                                },
                                is_negated: None,
                                operator: Some(OPERATOR::OR),
                                search_identifier: None,
                                nested_detections: Some(Detection {
                                    operator: None,
                                    conditions: Some(vec![
                                        Condition {
                                            metadata: Metadata {
                                                parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
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
                Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::AND,
                        parser_result: "and not filter_scmevent".to_string()
                    },
                    is_negated: Some(true),
                    operator: Some(OPERATOR::AND),
                    search_identifier: Some("filter_scmevent".to_string()),
                    nested_detections: None
                }
            ])
        }))
    }

    #[test]
    fn run_parse_for_parens_condition() {
        let result = parse("Not Keywords or (Selection and not Filter) or Selection1");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(OPERATOR::OR),
                conditions: Some(vec![
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::NOT,
                            parser_result: "Not Keywords".to_string()
                        },
                        is_negated: Some(true),
                        operator: None,
                        search_identifier: Some("Keywords".to_string()),
                        nested_detections: None
                    },
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::OR,
                            parser_result: "or (Selection and not Filter)".to_string()
                        },
                        is_negated: None,
                        operator: Some(OPERATOR::OR),
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(OPERATOR::AND),
                            conditions: Some(vec![
                                Condition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                                        parser_result: "Selection".to_string()
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("Selection".to_string()),
                                    nested_detections: None
                                },
                                Condition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::AND,
                                        parser_result: "and not Filter".to_string()
                                    },
                                    is_negated: Some(true),
                                    operator: Some(OPERATOR::AND),
                                    search_identifier: Some("Filter".to_string()),
                                    nested_detections: None
                                }
                            ])
                        })
                    },
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::OR,
                            parser_result: "or Selection1".to_string()
                        },
                        is_negated: None,
                        operator: Some(OPERATOR::OR),
                        search_identifier: Some("Selection1".to_string()),
                        nested_detections: None
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_or_not() {
        let result = parse("Selection or not Filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(OPERATOR::OR),
                conditions: Some(vec![
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                            parser_result: "Selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
                    },
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::OR,
                            parser_result: "or not Filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(OPERATOR::OR),
                        search_identifier: Some("Filter".to_string()),
                        nested_detections: None
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_and_not() {
        let result = parse("Selection and not Filter");
        assert_eq!(
            result,
            Ok(Detection {
                operator: Some(OPERATOR::AND),
                conditions: Some(vec![
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                            parser_result: "Selection".to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: Some("Selection".to_string()),
                        nested_detections: None
                    },
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::AND,
                            parser_result: "and not Filter".to_string()
                        },
                        is_negated: Some(true),
                        operator: Some(OPERATOR::AND),
                        search_identifier: Some("Filter".to_string()),
                        nested_detections: None
                    }
                ])
            })
        )
    }

    #[test]
    fn run_parse_for_search_id() {
        let result = parse("Selection");
        assert_eq!(
            result,
            Ok(Detection {
                operator: None,
                conditions: Some(vec![Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
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
