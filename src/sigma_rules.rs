use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use anyhow::Error;
use serde::{Serialize, Deserialize};
use serde::de::IntoDeserializer;
use serde_yaml::{Deserializer, Mapping, Number, Value};
use crate::yml::{self, deserialize_yml, is_yml};
use walkdir::{DirEntry, WalkDir};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
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
    authors: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    logsource: Logsource,
    #[serde(default)]
    detection: BTreeMap<String, DetectionTypes>,
    #[serde(default)]
    fields: String,
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
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum DetectionTypes {
    // #[serde(deserialize_with = "from_non_string_type")]
    String(String),
    Sequence(Vec<DetectionTypesTwo>),
    Mapping(Option<BTreeMap<String, DetectionTypesTwo>>),
}


// The next goal is to build a struct in between each enum, so that when the enum matches we can parse the next layer of objects
#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct DTypesString {
    #[serde(default)]
    value: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum DetectionTypesTwo {
    // #[serde(deserialize_with = "from_non_string_type")]
    Number(u32),
    String(String),
    Sequence(Vec<String>),
    Mapping(BTreeMap<String, DetectionTypesThree>),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum DetectionTypesThree {
    // #[serde(deserialize_with = "from_non_string_type")]
    Number(u32),
    String(String),
    Sequence(Vec<String>),
    Mapping(BTreeMap<String, String>),
}


impl SigmaRule {

    // When parsing the de yml mapping, think of this nested logic
    // fn is_map() {}
    //     fn contains_list() {}
    //     fn contains_string(){}

    pub fn output_format() -> Result<(), Error> {

        let de_yml = deserialize_yml("test/assets/hard.yml".to_string())?;
        let yml_value = Value::deserialize(de_yml)?;


        dbg!("{:?}", yml_value);
        Ok(())
        // let sigmaRule = SigmaRule::build_sigma_rule(&yml_value);
    }


    // This adds all of the rules in the config/rules folder upon initialization
    pub fn add_rules<'de>(rulesDir: String) -> std::io::Result<()> {
        for file in WalkDir::new(rulesDir).into_iter().filter_map(|file| file.ok()) {
            if file.metadata().unwrap().is_file() && is_yml(&file) {
                let file = File::open(file.path().display().to_string())?;
                let reader = BufReader::new(file);
                // If an error in reading the yaml, error output to console and then continue() to next file
                let de_yml = serde_yaml::from_reader::<BufReader<File>, SigmaRule>(reader);
                println!("WOW = {:?}", de_yml.unwrap());
            }
        }

        Ok(())
    }

    // fn from_non_string_type<'de, D>() -> Result<Vec<String>, D::Error>
    //     where
    //         D: IntoDeserializer<'de>,
    // {
    //     let license_ids: Vec<&str> = Deserialize::deserialize(deserializer)?;
    //
    //     let mut licenses: Vec<License> = Vec::new();
    //
    //     for license_id in license_ids {
    //         let path = format!("example/licenses/{0}/{0}.yaml", license_id);
    //         let config = std::fs::File::open(&path)
    //             .map_err(D::Error::custom)?;
    //         let mut license: License = serde_yaml::from_reader(&config)
    //             .map_err(D::Error::custom)?;
    //         license.id = license_id.to_string();
    //         println!("{:?}", &license);
    //         licenses.push(license);
    //     }
    //
    //     Ok(licenses)
    // }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_detections_yml() {
        let yml = SigmaRule::add_rules("test/assets/simple.yml".to_string());
        assert_eq!(yml.is_ok(), true, "Simple yml returns as SigmaRule struct")
    }

    #[test]
    fn test_intermediate_detections_yml() {
        let yml = SigmaRule::add_rules("test/assets/intermediate.yml".to_string());
        assert_eq!(yml.is_ok(), true, "Intermediate yml returns as SigmaRule struct")
    }

    #[test]
    fn test_hard_detections_yml() {
        let yml = SigmaRule::add_rules("test/assets/hard.yml".to_string());
        assert_eq!(yml.is_ok(), true, "Hard yml returns as SigmaRule struct")
    }

}
