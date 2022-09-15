use crate::parsers::operator_parsers::{new_parser, not_parser, parser};
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
// #[derive(Clone, Debug, PartialEq)]
// struct Detections {
//     detections: Vec<Detection>,
// }

/// Contains the conditions for a single Detection.
#[derive(Clone, Debug, PartialEq)]
struct Detection {
    conditions: BTreeMap<Option<OPERATOR>, Vec<Condition>>,
}

/// Contains the condition and any nested conditions.
/// search_identifier will contain Some(String) if a detection key is matched.
/// search_identifier will be None in the event that parentheses follow a CONDITIONAL.
///     i.e. Selection and not (Keywords or Filter)
/// nested_detections will contain Some(BTreeMap<CONDITIONAL, Vec<Condition>>) in the event that parentheses follow a CONDITIONAL.
/// nested_detections will be None if a detection key is matched.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub(crate) parser_result: Option<Vec<String>>,
    pub(crate) is_negated: Option<bool>,
    pub(crate) operator: Option<OPERATOR>,
    pub(crate) search_identifier: Option<String>,
    pub(crate) nested_detections: Option<BTreeMap<Option<OPERATOR>, Vec<Condition>>>,
}


#[derive(Clone, Debug, PartialEq)]
pub enum OPERATOR {
    AND,
    OR,
}

impl OPERATOR {
    fn as_str(&self) -> &'static str {
        match self {
            OPERATOR::AND => "and",
            OPERATOR::OR => "or"
        }
    }
}


impl Detection {
    fn new() -> Detection {
        Detection { conditions: BTreeMap::new() }
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
            parser_result: None,
            search_identifier: None,
            is_negated: None,
            nested_detections: None,
            operator: None
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
fn parse_condition(remaining_condition: &str) -> () {

    let mut detection = Detection::new();
    let mut remaining_condition = remaining_condition;

    println!("Top Remaining Condition: {}", remaining_condition);
    // remaining_condition = "";

    // if parser(remaining_condition).is_ok() {
    //     remaining_condition = "";
    // }

    // println!("{:?}", condition);

    while !remaining_condition.is_empty() {

        let mut condition = Condition::new();

        match new_parser(remaining_condition) {
            Ok(nice) => {
                remaining_condition = nice.0;



                // currently thinking of how to know what to update, when to update, and how to keep the nestings.



                // alt(not_parser())

                // let test2 = parser(remaining_condition);
                // match test2 {
                //     Ok((remaining, returned)) => {}
                //     Err(..) => {}
                // }
                println!("rem = {:?}, ret = {:?}", nice.0, nice.1);
                // parser(remaining)
            }
            Err(..) => {}
        }
    }


    // Ok((remaining_condition, condition))
    ()
}

// Top Remaining Condition: Selection and not Filter
// Ok((" and not Filter", ConditionInput { input: Condition { parser_result: "Selection", is_negated: None, operator: None, search_identifier: Some("Selection"), nested_detections: None } }))
// rem = " and not Filter", ret = ConditionInput { input: Condition { parser_result: "Selection", is_negated: None, operator: None, search_identifier: Some("Selection"), nested_detections: None } }
// Ok((" not Filter", ConditionInput { input: Condition { parser_result: "and", is_negated: None, operator: Some(AND), search_identifier: None, nested_detections: None } }))
// rem = " not Filter", ret = ConditionInput { input: Condition { parser_result: "and", is_negated: None, operator: Some(AND), search_identifier: None, nested_detections: None } }
// Ok((" Filter", ConditionInput { input: Condition { parser_result: "not", is_negated: None, operator: None, search_identifier: Some("not"), nested_detections: None } }))
// rem = " Filter", ret = ConditionInput { input: Condition { parser_result: "not", is_negated: None, operator: None, search_identifier: Some("not"), nested_detections: None } }
// Ok(("", ConditionInput { input: Condition { parser_result: "Filter", is_negated: None, operator: None, search_identifier: Some("Filter"), nested_detections: None } }))
// rem = "", ret = ConditionInput { input: Condition { parser_result: "Filter", is_negated: None, operator: None, search_identifier: Some("Filter"), nested_detections: None } }
// ()

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

    // start here for current implementation that is being worked on. All code within the fn parse_condition() is relevant
    #[test]
    fn parse_condition_test() {
        let nice = parse_condition("Selection and not Filter");
        println!("{:?}", nice);
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
