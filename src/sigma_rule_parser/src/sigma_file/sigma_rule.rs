use anyhow::Error;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use walkdir::WalkDir;
use crate::sigma_file::yml::is_yml;
use crate::structs::detection_logic::DetectionLogic;

#[derive(Default, Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(default)] // deny_unknown_fields in the future? currently unable to parse custom fields defined by individuals
pub struct SigmaRule {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub modified: String,
    #[serde(default)]
    pub logsource: Logsource,
    #[serde(default)]
    pub related: Vec<DetectionTypes>,
    #[serde(default)]
    pub detection: BTreeMap<String, DetectionTypes>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
    #[serde(default)]
    pub level: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Logsource {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub definition: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(untagged)]
pub enum DetectionTypes {
    Boolean(bool),
    Number(u64),
    String(String),
    Sequence(Vec<DetectionTypes>),
    Mapping(Option<BTreeMap<String, DetectionTypes>>),
}

pub fn process_sigma_rules<'de>(rules_dir: String) -> Result<Vec<SigmaRule>, Error> {
    let mut sigma_rules = Vec::new();
    for file in WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|file| file.ok())
    {
        if file.metadata().unwrap().is_file() && is_yml(&file) {
            let file_path = &file.path().display().to_string();
            let sigma_rule = read_rule_file(file_path);

            match sigma_rule {
                Ok(rule) => {
                    if initial_rule_validation(&rule) {
                        sigma_rules.push(rule)
                    } else {
                        info!("Rule is invalid. Please check required fields at https://github.com/SigmaHQ/sigma/wiki/Specification for {}.", file_path);
                        continue;
                    }
                }
                Err(error) => {
                    info!("Error loading rule {}. - {}", file_path, error);
                    continue; // skip to the next rule
                }
            }
        }
    }

    Ok(sigma_rules)
}


// TODO: Upate all consumers of read_rule_file to propagate error and skip to the next Sigma rule file
fn read_rule_file(file_path: &str) -> Result<SigmaRule, Error> {
    let file = File::open(file_path).unwrap();
    let reader = BufReader::new(file);
    let de_yml = serde_yaml::from_reader::<BufReader<File>, SigmaRule>(reader).unwrap();
    // info!(" = {:?}", de_yml);

    Ok(de_yml)
}

// https://github.com/SigmaHQ/sigma/wiki/Specification#value-modifiers
fn initial_rule_validation(rule: &SigmaRule) -> bool {
    if rule.title == "" || rule.id == "" || rule.detection.is_empty() {
        return false;
    }

    return true;
}

/// Conditions are returned by the yml processor as the Enum DetectionTypes.
/// This method extracts the type that the value is stored in and stringifies the value.
pub fn read_condition(condition: &DetectionTypes) -> &str {
    let condition_value = match condition {
        DetectionTypes::Boolean(condition) => stringify!(condition),
        DetectionTypes::Number(condition) => stringify!(condition),
        DetectionTypes::String(condition) => condition as &str,
        DetectionTypes::Sequence(_) => "",
        DetectionTypes::Mapping(_) => "",
    };

    condition_value
}


// where does this ultimately belong
// TODO: THIS BELONGS IN A COMPLETELY DIFFERENT LOCATION, ENTIRELY UNRELATED TO SIGMA_RULE.RS!!!!!!!!!!
pub fn read_search_identifiers(logic: &DetectionTypes) -> DetectionLogic {

    let mut detection_logic = DetectionLogic::init();

    let condition_value = match logic {
        DetectionTypes::Mapping(condition) => {
            let vec = condition.as_ref().unwrap();
            for (field, okie) in vec {
                let swag = read_search_identifiers(&okie);
                println!("m! {:?}", okie);
            }
            println!("Mapping: {:?}", vec);
        },
        //TODO - Sequence should be supported as defined in the spec, a list of conditions joins as OR conditionals
        DetectionTypes::Sequence(condition) => {
            let vec = condition.to_vec();
            println!("Vector: {:?}", vec);
            for okie in vec {
                let swag = read_search_identifiers(&okie);
                println!("v! {:?}", okie);
            }
        },
        DetectionTypes::Boolean(condition) => {},
        DetectionTypes::Number(condition) => {},
        DetectionTypes::String(condition) => {},
    };

    detection_logic
}

#[cfg(test)]
mod tests {
    use std::env::current_dir;
    use serde_yaml::{Mapping, Number, Sequence};
    use super::*;

    // #[test]
    // fn read_condition_sequence_type() {
    //     let rules = process_sigma_rules("src/sigma_file/test/assets/mimikatz.yml".to_string()).unwrap();
    //     for rule in rules {
    //         for (search_identifier, detection) in rule.detection {
    //             let result = read_search_identifiers(&detection);
    //         }
    //     }
    // }

    #[test]
    fn read_rule_yml_file_and_validate_title() -> Result<(), Error> {
        let rule = read_rule_file("src/sigma_file/test/assets/mimikatz.yml");
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(
            rule?.title, "Mimikatz through Windows Remote Management",
            "Validate title"
        );
        Ok(())
    }

    // An invalid rule is one that is missing a required field, such as the title.
    // Read more about rule formatting here - https://github.com/SigmaHQ/sigma/wiki/Specification
    #[test]
    fn read_rule_yml_file_handles_invalid_rule() -> Result<(), Error> {
        let rule =
            read_rule_file("src/sigma_file/test/assets/invalid_rules/invalid_title.yml");
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(rule?.title, "", "Validate title is empty string");
        Ok(())
    }

    #[test]
    fn retrieve_all_sigma_yml_rules_in_dir() -> Result<(), Error> {
        let sigma_rules =
            process_sigma_rules("src/sigma_file/test/assets/do_not_modify_folder".to_string());
        assert_eq!(sigma_rules.is_ok(), true, "Sigma Rule vec is ok");
        assert_eq!(
            sigma_rules?.len(),
            1,
            "Confirm length of rules in vec is equal to one, invalid rule should NOT be stored."
        );
        Ok(())
    }

    #[test]
    fn valid_rule_initial_validation() -> Result<(), Error> {
        let rule = read_rule_file("src/sigma_file/test/assets/mimikatz.yml");
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_valid = initial_rule_validation(&rule.unwrap());
        assert_eq!(is_valid, true, "Sigma rule is valid");
        Ok(())
    }

    #[test]
    fn invalid_title_rule_initial_validation() -> Result<(), Error> {
        let rule =
            read_rule_file("src/sigma_file/test/assets/invalid_rules/invalid_title.yml");
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = initial_rule_validation(&rule.unwrap());
        assert_eq!(is_invalid, false, "Sigma rule is invalid due to the title");
        Ok(())
    }

    #[test]
    fn invalid_id_rule_initial_validation() -> Result<(), Error> {
        let rule =
            read_rule_file("src/sigma_file/test/assets/invalid_rules/invalid_id.yml");
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = initial_rule_validation(&rule.unwrap());
        assert_eq!(is_invalid, false, "Sigma rule is invalid  due to the id");
        Ok(())
    }

    #[test]
    fn invalid_detection_rule_initial_validation() -> Result<(), Error> {
        let rule = read_rule_file(
            "src/sigma_file/test/assets/invalid_rules/invalid_detection.yml",
        );
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = initial_rule_validation(&rule.unwrap());
        assert_eq!(
            is_invalid, false,
            "Sigma rule is invalid due to the detection"
        );
        Ok(())
    }
}
