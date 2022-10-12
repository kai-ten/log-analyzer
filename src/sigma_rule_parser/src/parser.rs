use std::collections::BTreeMap;
use crate::structs::detection_condition::DetectionCondition;
use crate::structs::detection::Detection;
use crate::detection_parsers::sub_parsers::parser;
use std::fmt::Error;
use log::{info, warn};
use crate::detection_parsers::condition_parser::parse_detection_condition;
use crate::sigma_file::sigma_rule::read_condition;
use crate::structs::detection_metadata::ParserTypes;
use crate::structs::sigma_rule::{SigmaRule, YmlTypes};


// Result<Detection, Error>
pub fn parse(rule: SigmaRule) -> Result<(), Error> {

    let rule_id = rule.id;
    let mut raw_detection = rule.detection;

    let condition = raw_detection.get("condition").unwrap();
    let condition = read_condition(condition).to_string();
    raw_detection.remove("condition");


    // pass in list of search_identifiers to confirm if it exists for SEARCH_IDENTIFIER match
    let search_identifiers = raw_detection.into_keys().collect::<Vec<String>>();
    println!("sid: {:?}", search_identifiers);

    // TODO: add search_identifiers to the input (via tuple maybe?), then handle the value downstream in tests
    let detection = parse_detection_condition(condition.as_str(), search_identifiers);
    println!("PARSE! {:?}", detection);


    Ok(())
}


/// These tests are real scenarios of conditions that have been written in Sigma rules.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use serde_yaml::{Mapping, Number, Sequence};
    use crate::parser::parse;
    use crate::sigma_file::sigma_rule::process_sigma_rules;
    use crate::structs::detection_condition::{DetectionCondition, Operator};
    use crate::structs::detection::Detection;
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::detection_metadata::{DetectionMetadata, ParserTypes};


    #[test]
    fn parse_rule() {
        let sigma_rules =
            process_sigma_rules("src/sigma_file/test/assets/mimikatz.yml".to_string()).unwrap();
        for rule in sigma_rules {
            parse(rule);
        }
    }

    // Will this work for testing the detections part?
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



}
