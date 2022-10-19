use std::fmt::Error;
use log::{info, warn};
use crate::detection_parsers::condition::condition_parser::parse_detection_condition;
use crate::detection_parsers::logic::logic_parser::parse_detection_logic;
use crate::sigma_file::sigma_rule::read_condition;
use crate::structs::detection::Detection;
use crate::structs::sigma_rule::SigmaRule;


// Result<Detection, Error>
pub fn build(rule: SigmaRule) -> Result<Detection, Error> {

    let rule_id = rule.id;
    let mut raw_detection = rule.detection;

    let condition = raw_detection.get("condition").unwrap();
    let condition = read_condition(condition).to_string();
    raw_detection.remove("condition");

    /// search identifiers are used to validate whether or not a condition contains existing search id's
    let search_identifiers = raw_detection.clone().into_keys().collect::<Vec<String>>();
    let mut detection = parse_detection_condition(condition.as_str(), search_identifiers)?;
    println!("PARSE! {:?}", detection.clone());


    // MUST NOW ITERATE THROUGH A DETECTION, FIND ALL SEARCH IDENTIFIERS, THEN SAVE THE LOGIC TO THE DETECTIONCONDITION
    let test_detection_logic_result = parse_detection_logic(&mut detection, raw_detection.clone());
    println!("it works - {:?}", test_detection_logic_result);
    Ok(detection)
}


/// These tests are real scenarios of conditions that have been written in Sigma rules.
#[cfg(test)]
mod tests {
    use crate::detection_builder::build;
    use crate::sigma_file::sigma_rule::process_sigma_rules;

    #[test]
    fn lazy_logic_parser_test() {
        let sigma_rules = process_sigma_rules("src/sigma_file/test/assets/detection_logic/parse_detection_logic.yml".to_string()).unwrap();
        for rule in sigma_rules {
            build(rule);
        }
    }

    #[test]
    fn parse_rule() {
        let sigma_rules = process_sigma_rules("src/sigma_file/test/assets/mimikatz.yml".to_string()).unwrap();
        for rule in sigma_rules {
            build(rule);
        }
    }
}
