use std::collections::BTreeMap;
use crate::structs::detection_condition::{DetectionCondition, ParserTypes};
use crate::structs::detection::Detection;
use crate::condition_parsers::sub_parsers::parser;
use std::fmt::Error;
use log::{info, warn};
use crate::sigma_file::sigma_rule::{DetectionTypes, read_condition, read_search_identifiers, SigmaRule};


// this will receive the rule, which will then pass the necessary parsers to the next layer
// Result<Detection, Error>
pub fn parse(rule: SigmaRule) -> Result<(), Error> {

    let rule_id = rule.id;
    let detection = rule.detection;
    let search_identifiers = detection.keys();
    println!("sids: {:?}", search_identifiers); // ["condition", "filter", "selection", "selection1", "selection2"]

    let processed_condition = process_condition(detection.clone());
    println!("sa {:?}", processed_condition);

    // pass in list of search_identifiers to confirm if it exists for SEARCH_IDENTIFIER match
    let ok = parse_detection_condition(processed_condition.unwrap().as_str());
    println!("PARSE! {:?}", ok);


    let munn3y = detection.clone();
    println!("MONEY: {:?}", munn3y);


    // for (key, value) in detection {
    //     println!("K: {:?} : V: {:?}", key, value);
    //     let nice = read_search_identifiers(&value);
    //     println!("cond: {:?}", nice);
    // }

    Ok(())
}

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
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE");
                    }
                    ParserTypes::SearchIdentifier => {
                        // create detection logic here
                        // let mut condition = parser_output.result;
                        // condition.detection_logic = parse_detection_logic();
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

// MONEY: {"condition": String("selection and not filter and keywords"), "filter": Mapping(Some({"EventID": Sequence([Number(456), Number(876)])})), "selection": Sequence([Mapping(Some({"SourceImage": String("C:\\Windows\\system32\\wsmprovhost.exe"), "TargetImage|endswith": Sequence([String("\\lsass.exe"), String("test.exe")])}))]), "selection1": Sequence([String("EVIL"), String("Service")]), "selection2": Sequence([Mapping(Some({"TargetImage|endswith": Sequence([String("\\lsass.exe"), String("test.exe")])})), Mapping(Some({"SourceImage": String("C:\\Windows\\system32\\wsmprovhost.exe")}))])}


fn parse_detection_logic() {

}

fn process_condition(
    detection: BTreeMap<String, DetectionTypes>,
) -> Result<String, Error> {
    let condition = detection.get("condition").unwrap();
    let condition_value = read_condition(condition).to_string();

    Ok(condition_value)
}


/// These tests are real scenarios of conditions that have been written in Sigma rules.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use serde_yaml::{Mapping, Number, Sequence};
    use crate::parser::{parse, parse_detection_condition};
    use crate::sigma_file::sigma_rule::{Logsource, process_sigma_rules, SigmaRule};
    use crate::structs::detection_condition::{DetectionCondition, Metadata, Operator, ParserTypes};
    use crate::structs::detection::Detection;


    #[test]
    fn parse_rule() {
        let sigma_rules =
            process_sigma_rules("../../config/rules/proc_access_win_mimikatz_through_winrm.yml".to_string()).unwrap();
        for rule in sigma_rules {
            parse(rule);
        }
    }

    // fn new_sigma_rule() -> SigmaRule {
    //     SigmaRule {
    //         title: "Mimikatz through Windows Remote Management".to_string(),
    //         id: "aa35a627-33fb-4d04-a165-d33b4afca3e8".to_string(),
    //         status: "stable".to_string(),
    //         description: "Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.".to_string(),
    //         references: vec!["https://pentestlab.blog/2018/05/15/lateral-movement-winrm/".to_string()],
    //         tags: vec![
    //             "attack.credential_access".to_string(),
    //             "attack.execution".to_string(),
    //             "attack.t1003.001".to_string(),
    //             "attack.t1059.001".to_string(),
    //             "attack.lateral_movement".to_string(),
    //             "attack.t1021.006".to_string(),
    //             "attack.s0002".to_string()],
    //         author: "Patryk Prauze - ING Tech".to_string(),
    //         date: "2019/05/20".to_string(),
    //         modified: "2021/06/21".to_string(),
    //         logsource: Logsource {
    //             category: "process_access".to_string(),
    //             product: "windows".to_string(),
    //             service: "".to_string(),
    //             definition: "".to_string() },
    //         related: vec![],
    //         detection: {
    //             "condition": "selection and not filter and keywords",
    //             "filter".to_string(): Mapping(Some({"EventID": Sequence([Number(456), Number(876)])})), "selection": Sequence([Mapping(Some({"SourceImage": String("C:\\Windows\\system32\\wsmprovhost.exe"), "TargetImage|endswith": Sequence([String("\\lsass.exe"), String("test.exe")])}))]), "selection1": Sequence([String("EVIL"), String("Service")]), "selection2": Sequence([Mapping(Some({"TargetImage|endswith": Sequence([String("\\lsass.exe"), String("test.exe")])})), Mapping(Some({"SourceImage": String("C:\\Windows\\system32\\wsmprovhost.exe")}))])}, fields: [], falsepositives: ["Unlikely"], level: "high" }
    // }


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
        let result = parse_detection_condition("Not Keywords or (Selection and not Filter) or Selection1");
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
