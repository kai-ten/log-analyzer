use sigma_rule_parser::operator_parsers::parser;
use crate::sigma_rule::DetectionTypes;
use crate::SigmaRule;
use anyhow::Error;
use log::info;
use nom::branch::alt;
use nom::IResult;
use std::collections::BTreeMap;
use std::vec;
use sigma_rule_parser::structs::condition::{Condition, PARSER_TYPES};
use sigma_rule_parser::structs::detection::Detection;

pub fn process_detection(sigma_rules: Vec<SigmaRule>) -> Result<(), Error> {
    // let Detections = Detections::new();

    let detection = Detection::new();

    for rule in sigma_rules {
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

        let mut detection = Detection::new();

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


// Ignore process_condition for now, put loop in here and try to complete implementation for recursion
pub fn parse_detection(rule_condition: &str) -> Result<Detection, Error> {

    let mut detection = Detection::new();
    let mut remaining_condition = rule_condition;

    println!("Initial condition: {}", remaining_condition);

    while !remaining_condition.is_empty() {

        match parser(remaining_condition) {
            Ok((remaining, condition)) => {

                remaining_condition = remaining;
                let mut condition_result = Condition::new();

                match condition.parser_type.as_ref().unwrap() {
                    PARSER_TYPES::PARENS => {
                        condition_result.nested_detections = condition.nested_detections.clone();
                        detection.conditions = Some(vec![condition.input]);
                    },
                    PARSER_TYPES::ONE_OF_THEM => {
                        println!("ONE_OF_THEM");
                    },
                    PARSER_TYPES::ALL_OF_THEM => {
                        println!("ALL_OF_THEM");
                    },
                    PARSER_TYPES::ONE_OF => {
                        println!("ONE_OF");
                    },
                    PARSER_TYPES::ALL_OF => {
                        println!("ALL_OF");
                    },
                    PARSER_TYPES::NOT => {
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition_result);
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::AND => {
                        detection.operator = condition.operator.clone();
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition_result);
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::OR => {
                        detection.operator = condition.operator.clone();
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition_result);
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::PIPE => {
                        println!("PIPE SHOULD RETURN ERROR")
                    },
                    PARSER_TYPES::SEARCH_IDENTIFIER => {
                        detection.conditions = Some(vec![condition.input]);
                    },
                    _ => println!("I DONT KNOW YET")
                }
            }
            Err(..) => {}
        }
    }


    println!("DETECTION: {:?}", detection);
    // Ok((remaining_condition, condition))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_detection_testdd() {
        // let result = parse_detection("Selection");
        // println!("{:?}", result);
        //
        // let result = parse_detection("Not Selection");
        // println!("{:?}", result);
        //
        // let result = parse_detection("Selection and not Filter");
        // println!("{:?}", result);

        let result = parse_detection("Selection and Keywords");
        println!("{:?}", result);

        let result = parse_detection("(Selection or not Filter) and Keywords");
        println!("{:?}", result);
    }

    #[test]
    fn initialize_parser_logic() {
        initialize_parser("ok");
    }

    // #[test]
    // fn testa90() {
    //     let rule = SigmaRule {
    //         title: "Startup Items",
    //         id: "dfe8b941-4e54-4242-b674-6b613d521962",
    //         status: "test",
    //         description: "Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.",
    //         references: ["https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.005/T1037.005.md"],
    //         tags: ["attack.persistence", "attack.privilege_escalation", "attack.t1037.005"],
    //         author: "Alejandro Ortuno, oscd.community",
    //         date: "2020/10/14",
    //         modified: "2022/07/11",
    //         logsource: Logsource { category: "file_event", product: "macos", service: "", definition: "" }, related: [], detection: {"condition": String("selection"), "selection": Sequence([Mapping(Some({"TargetFilename|contains": String("/Library/StartupItems/")})), Mapping(Some({"TargetFilename|endswith": String(".plist")}))])}, fields: [], falsepositives: ["Legitimate administration activities"], level: "low" };
    // }

    #[test]
    fn read_string_condition() {}
}
