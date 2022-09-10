use crate::parsers::operator_parsers::{not_parser, parser};
use crate::sigma_rule::DetectionTypes;
use crate::SigmaRule;
use anyhow::Error;
use log::info;
use nom::branch::alt;
use nom::IResult;
use std::collections::BTreeMap;
use std::vec;

// for the whole rule

/// Contains the detections for all rules.
/// This struct is compared to incoming logs to determine if there is a match or not.
#[derive(Debug)]
struct Detections {
    detections: Vec<Detection>,
}

/// Contains the conditions for a single Detection.
#[derive(Debug)]
struct Detection {
    conditions: Option<BTreeMap<CONDITIONAL, Vec<Condition>>>,
}

/// Contains the condition and any nested conditions.
/// search_identifier will contain Some(String) if a detection key is matched.
/// search_identifier will be None in the event that parentheses follow a CONDITIONAL.
///     i.e. Selection and not (Keywords or Filter)
/// nested_detections will contain Some(BTreeMap<CONDITIONAL, Vec<Condition>>) in the event that parentheses follow a CONDITIONAL.
/// nested_detections will be None if a detection key is matched.
#[derive(Debug, PartialEq)]
pub struct Condition {
    search_identifier: Option<String>,
    is_negated: bool,
    nested_detections: Option<BTreeMap<CONDITIONAL, Vec<Condition>>>,
}

// Operator? - can these include x/all of
#[derive(Debug, PartialEq)]
enum CONDITIONAL {
    AND,
    OR,
}

// const AND: &'static str = "and";
// const OR: &'static str = "or";

/*
Create detection based on the condition(s)
*/

impl Detections {
    fn new() -> Detections {
        Detections { detections: vec![] }
    }

    fn update() -> () {}
}

impl Detection {
    fn new() -> Detection {
        Detection { conditions: None }
    }

    // fn modify(&mut self) -> Detection {
    //     Detection {
    //         search_identifier,
    //         negation,
    //         nested_detections
    //     }
    // }
}

impl Condition {
    pub fn new() -> Condition {
        Condition {
            search_identifier: None,
            is_negated: false,
            nested_detections: None,
        }
    }

    // fn update(condition: &mut Condition) -> Condition {
    //     condition.search_identifier =
    // }

    // fn modify(&mut self) -> Detection {
    //     Detection {
    //         search_identifier,
    //         negation,
    //         nested_detections
    //     }
    // }
}

pub fn process_detection(sigma_rules: Vec<SigmaRule>) -> Result<(), Error> {
    let Detections = Detections::new();

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

fn parse_condition(remaining_condition: &str) -> Result<(&str, Condition), Error> {
    let mut condition = Condition::new();
    let mut remaining_condition = remaining_condition;
    // how to create this condition and store it in the detection 'right above it'
    // the btree? yep
    // i think i know how
    // Detections.detections.ins
    println!("Top Remaining Condition: {}", remaining_condition);
    // remaining_condition = "";

    // if parser(remaining_condition).is_ok() {
    //     remaining_condition = "";
    // }

    println!("{:?}", condition);

    match parser(remaining_condition) {
        Ok((remaining, returned)) => {
            remaining_condition = remaining;

            // alt(not_parser())

            // let test2 = parser(remaining_condition);
            // match test2 {
            //     Ok((remaining, returned)) => {}
            //     Err(..) => {}
            // }
            println!("rem = {:?}, ret = {:?}", remaining, returned);
            // parser(remaining)
        }
        Err(..) => {}
    }

    Ok((remaining_condition, condition))
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
    fn parse_condition_test() {
        let _ = parse_condition("Not Selection and (Filter or Keyword)");
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
