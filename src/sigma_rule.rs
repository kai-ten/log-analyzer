use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use anyhow::Error;
use serde::{Serialize, Deserialize};
use crate::yml::is_yml;
use walkdir::WalkDir;
use log::info;

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]               // deny_unknown_fields in the future? currently unable to parse custom fields defined by individuals
pub struct SigmaRule {
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) references: Vec<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) author: String,
    #[serde(default)]
    pub(crate) date: String,
    #[serde(default)]
    pub(crate) modified: String,
    #[serde(default)]
    pub(crate) logsource: Logsource,
    #[serde(default)]
    pub(crate) related: Vec<DetectionTypes>,
    #[serde(default)]
    pub(crate) detection: BTreeMap<String, DetectionTypes>,
    #[serde(default)]
    pub(crate) fields: Vec<String>,
    #[serde(default)]
    pub(crate) falsepositives: Vec<String>,
    #[serde(default)]
    pub(crate) level: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Logsource {
    #[serde(default)]
    pub(crate) category: String,
    #[serde(default)]
    pub(crate) product: String,
    #[serde(default)]
    pub(crate) service: String,
    #[serde(default)]
    pub(crate) definition: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(untagged)]
pub enum DetectionTypes {
    #[serde(rename = "Number")]
    Boolean(bool),
    #[serde(rename = "Number")]
    Number(u64),
    #[serde(rename = "String")]
    String(String),
    #[serde(rename = "Sequence")]
    Sequence(Vec<DetectionTypes>),
    #[serde(rename = "Mapping")]
    Mapping(Option<BTreeMap<String, DetectionTypes>>),
}


impl SigmaRule {

    pub fn process_sigma_rules<'de>(rules_dir: String) -> Result<Vec<SigmaRule>, Error> {
        let mut sigma_rules = Vec::new();
        for file in WalkDir::new(rules_dir).into_iter().filter_map(|file| file.ok()) {
            if file.metadata().unwrap().is_file() && is_yml(&file) {
                let file_path = &file.path().display().to_string();
                let sigma_rule = SigmaRule::read_rule_file(file_path);

                match sigma_rule {
                    Ok(rule) => {
                        if SigmaRule::initial_rule_validation(&rule) {
                            sigma_rules.push(rule)
                        } else {
                            info!("Rule is invalid. Please check required fields at https://github.com/SigmaHQ/sigma/wiki/Specification for {}.", file_path);
                            continue;
                        }
                    },
                    Err(error) => {
                        info!("Error loading rule {}. - {}", file_path, error);
                        continue; // skip to the next rule
                    }
                }
            }
        }

        Ok(sigma_rules)
    }

    fn read_rule_file(file_path: &String) -> Result<SigmaRule, Error> {
        let file = File::open(file_path)?;
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
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_rule_yml_file_and_validate_title() -> Result<(), Error> {
        let rule = SigmaRule::read_rule_file(&"test/assets/mimikatz.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(rule?.title, "Mimikatz through Windows Remote Management", "Validate title");
        Ok(())
    }

    // An invalid rule is one that is missing a required field, such as the title.
    // Read more about rule formatting here - https://github.com/SigmaHQ/sigma/wiki/Specification
    #[test]
    fn read_rule_yml_file_handles_invalid_rule() -> Result<(), Error> {
        let rule = SigmaRule::read_rule_file(&"test/assets/invalid_rules/invalid_title.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(rule?.title, "", "Validate title is empty string");
        Ok(())
    }

    #[test]
    fn retrieve_all_sigma_yml_rules_in_dir() -> Result<(), Error>  {
        let sigma_rules = SigmaRule::process_sigma_rules("test/assets/do_not_modify_folder".to_string());
        assert_eq!(sigma_rules.is_ok(), true, "Sigma Rule vec is ok");
        assert_eq!(sigma_rules?.len(), 1, "Confirm length of rules in vec is equal to one, invalid rule should NOT be stored.");
        Ok(())
    }

    #[test]
    fn valid_rule_initial_validation() -> Result<(), Error>  {
        let rule = SigmaRule::read_rule_file(&"test/assets/mimikatz.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_valid = SigmaRule::initial_rule_validation(&rule.unwrap());
        assert_eq!(is_valid, true, "Sigma rule is valid");
        Ok(())
    }

    #[test]
    fn invalid_title_rule_initial_validation() -> Result<(), Error>  {
        let rule = SigmaRule::read_rule_file(&"test/assets/invalid_rules/invalid_title.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = SigmaRule::initial_rule_validation(&rule.unwrap());
        assert_eq!(is_invalid, false, "Sigma rule is invalid due to the title");
        Ok(())
    }

    #[test]
    fn invalid_id_rule_initial_validation() -> Result<(), Error>  {
        let rule = SigmaRule::read_rule_file(&"test/assets/invalid_rules/invalid_id.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = SigmaRule::initial_rule_validation(&rule.unwrap());
        assert_eq!(is_invalid, false, "Sigma rule is invalid  due to the id");
        Ok(())
    }

    #[test]
    fn invalid_detection_rule_initial_validation() -> Result<(), Error>  {
        let rule = SigmaRule::read_rule_file(&"test/assets/invalid_rules/invalid_detection.yml".to_string());
        assert_eq!(rule.is_ok(), true, "yml returns as SigmaRule struct");

        let is_invalid = SigmaRule::initial_rule_validation(&rule.unwrap());
        assert_eq!(is_invalid, false, "Sigma rule is invalid due to the detection");
        Ok(())
    }

}
