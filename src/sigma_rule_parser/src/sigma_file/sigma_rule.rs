use anyhow::Error;
use log::info;
use std::fs::File;
use std::io::BufReader;
use walkdir::WalkDir;
use crate::sigma_file::yml::is_yml;
use crate::structs::detection_logic::DetectionLogic;
use crate::structs::sigma_rule::{SigmaRule, YmlTypes};


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


// TODO: Update all consumers of read_rule_file to propagate error and skip to the next Sigma rule file
fn read_rule_file(file_path: &str) -> Result<SigmaRule, Error> {
    let file = File::open(file_path.clone()).unwrap();
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
/// TODO: Turn this into a Result<&str, Error> response, handle error by continuing to next rule and outputting error message
pub fn read_condition(condition: &YmlTypes) -> &str {
    let condition_value = match condition {
        YmlTypes::Boolean(condition) => stringify!(condition),
        YmlTypes::Number(condition) => stringify!(condition),
        YmlTypes::String(condition) => condition as &str,
        YmlTypes::Sequence(_) => "",
        YmlTypes::Mapping(_) => "",
        _ => ""
    };

    condition_value
}


#[cfg(test)]
mod tests {
    use std::env::current_dir;
    use serde_yaml::{Mapping, Number, Sequence};
    use super::*;


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

    //TODO: Change this test to an Error assert_eq, make other tests like this one
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
