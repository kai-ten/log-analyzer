

// Search identifiers represent rules to apply to the log - maps or lists


// Load the detections here
// How to compare the detections with the logs that are coming in?????

/*
THE RULES FOR CREATING A DETECTION:
Create rules based on the following.

a. Get the Condition(s) of the detection
    I. Must parse Condition with these rules..
    II. AND, OR
    III. all of <search_identifier> / 1 of <search_identifier> - make list into an and
    IV. all of them / 1 of them - applies to all search identifiers
    V. all of <search_identifier_pattern> / 1 of <search_identifier_pattern>
    VI. NOT
    VII. Brackets to join - selectino1 and (ketwords1 or keywords2)
    VIII. If pipe |, return that we don't support deprecation and will be using Sigma Correlations
b. The condition will build the querying that takes place for the log
*/

/*
THE RULES FOR PROCESSING DETECTIONS:
1. The log data format should be json, so must use serde_json to deserialize, set value to string, lowercase, then compare with detections
2. For each detection...
    a. Get the Condition(s) of the detection
        I. Must parse Condition with these rules..
        II. AND, OR
        III. all of <search_identifier> / 1 of <search_identifier> - make list into an and
        IV. all of them / 1 of them - applies to all search identifiers
        V. all of <search_identifier_pattern> / 1 of <search_identifier_pattern>
        VI. NOT
        VII. Brackets to join - selectino1 and (ketwords1 or keywords2)
        VIII. If pipe |, return that we don't support deprecation and will be using Sigma Correlations
     b. The condition will build the querying that takes place for the log
*/

use std::collections::BTreeMap;
use anyhow::Error;
use log::info;
use crate::sigma_rule::DetectionTypes;
use crate::SigmaRule;

pub struct Detection {
    rule_title: String,
    rule_id: String,
}

struct Condition {
    search_ids: Vec<SearchID>,
    alert: bool,
}

struct SearchID {
    string_value: String,
    vec_value: Vec<String>,
    operator: String,
    negation: bool,
    modifiers: Vec<String>
}



const AND: &'static str = "and";
const OR: &'static str = "or";


/*
Create detection based on the condition(s)
*/
impl Detection {

    // check if condition exists first
    // then parse condition + all rules
    pub fn process_detection(sigma_rules: Vec<SigmaRule>) -> Result<(), Error> {
        for rule in sigma_rules {
            // println!("Detection - {:?}", rule.detection);
            // println!("{:?}", rule.detection.contains_key("condition"));

            // selection and not filter
            // Must figure out how to handle the logic of the search identifiers
            let rule_id = rule.id;
            let detection = rule.detection;

            // match on process_condition, if Some then keep processing, if None then continue;
            let ok = match Detection::process_condition(rule_id, detection) {
                Some(_) => (),
                None => {continue;}
            };


            // for (k, v) in detection {
            //     println!("Detections - {:?} - {:?}", k, v);
            //
            // }
            break; // this break is only here for testing
        }

        Ok(())
    }

    fn process_condition(rule_id: String, detection: BTreeMap<String, DetectionTypes>) -> Option<()> {
        let a = if detection.contains_key("condition") {
            // parse condition method
            info!("{:?}", detection.get_key_value("condition"));
            info!("{:?}", detection.get("condition"));
            let condition = detection.get("condition");
            let condition_value = Detection::read_condition(condition);

            if condition_value != "" {
                Some(())
            } else {
                info!("Condition returned as empty string, this rule has been skipped - {:?}", rule_id);
                None
            }

        } else {
            info!("Detection must have a condition, this rule has been skipped - {:?}", rule_id);
            None
        };

        Some(())
    }

    fn read_condition(condition: Option<&DetectionTypes>) -> &str  {
        let condition_value = match condition.unwrap() {
            DetectionTypes::Boolean(condition) => stringify!(condition),
            DetectionTypes::Number(condition) => stringify!(condition),
            DetectionTypes::String(condition) => condition as &str,
            DetectionTypes::Sequence(_) => "",
            DetectionTypes::Mapping(_) => ""
        };

        condition_value
    }

    fn validate_condition_value() {

    }

}


#[cfg(test)]
mod tests {
    use super::*;

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
    fn read_string_condition() {

    }

}
