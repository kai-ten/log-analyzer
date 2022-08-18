use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use anyhow::Error;
use serde::{Serialize, Deserialize};
use serde_yaml::{Number, Value};
use crate::yml::is_yml;
use walkdir::WalkDir;

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]               // deny_unknown_fields in the future? currently unable to parse custom fields defined by individuals
pub struct SigmaRule {
    #[serde(default)]
    title: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    author: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    modified: String,
    #[serde(default)]
    logsource: Logsource,
    #[serde(default)]
    related: Vec<DetectionTypes>,
    #[serde(default)]
    detection: BTreeMap<String, DetectionTypes>,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    falsepositives: Vec<String>,
    #[serde(default)]
    level: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Logsource {
    #[serde(default)]
    category: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    definition: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum DetectionTypes {
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

    pub fn store_sigma_rules<'de>(rules_dir: String) -> Result<Vec<SigmaRule>, Error> {
        let mut sigma_rules = Vec::new();
        for file in WalkDir::new(rules_dir).into_iter().filter_map(|file| file.ok()) {
            if file.metadata().unwrap().is_file() && is_yml(&file) {
                let file_path = &file.path().display().to_string();
                let sigma_rule = SigmaRule::read_rule_file(file_path);
                match sigma_rule {
                    Ok(rule) => sigma_rules.push(rule),
                    Err(error) => {
                        println!("Error loading rule {:?}. - {:?}", file_path, error);
                        continue; // skip to the next rule
                    }
                }
            }
        }

        Ok(sigma_rules)
    }

    pub fn read_rule_file(file_path: &String) -> Result<SigmaRule, Error> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let de_yml = serde_yaml::from_reader::<BufReader<File>, SigmaRule>(reader).unwrap();
        // println!(" = {:?}", de_yml);

        Ok(de_yml)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_rule_yml_file_and_validate_title() -> Result<(), Error> {
        let yml = SigmaRule::read_rule_file(&"test/assets/mimikatz.yml".to_string());
        assert_eq!(yml.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(yml?.title, "Mimikatz through Windows Remote Management", "Validate title");
        Ok(())
    }

    // An invalid rule is one that is missing a required field, such as the title.
    // Read more about rule formatting here - https://github.com/SigmaHQ/sigma/wiki/Specification
    #[test]
    fn read_rule_yml_file_handles_invalid_rule() -> Result<(), Error> {
        let yml = SigmaRule::read_rule_file(&"test/assets/invalid_rule.yml".to_string());
        assert_eq!(yml.is_ok(), true, "yml returns as SigmaRule struct");
        assert_eq!(yml?.title, "", "Validate title is empty string");
        Ok(())
    }

    #[test]
    fn retrieve_all_sigma_yml_rules_in_dir() -> Result<(), Error>  {
        let sigma_rules = SigmaRule::store_sigma_rules("test/assets/do_not_modify_folder".to_string());
        assert_eq!(sigma_rules.is_ok(), true, "Sigma Rule vec is ok");
        assert_eq!(sigma_rules?.len(), 2, "Confirm length of rules in vec is equal to two.");
        Ok(())
    }

}
