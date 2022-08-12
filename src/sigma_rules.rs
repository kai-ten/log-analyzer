use std::collections::BTreeMap;
use std::io::BufReader;
use anyhow::Error;
use serde::{Serialize, Deserialize};
use serde_yaml::{Mapping, Value};
use crate::yml::{self, deserialize_yml, is_yml};
use walkdir::{DirEntry, WalkDir};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Logsource {
    category: Option<String>,
    product: Option<String>,
    service: Option<String>,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Detection {
    name: Option<String>,           // nuances about selection, other names (like filter), and condition
    value: Option<BTreeMap<String, Vec<Detection>>>,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
pub struct SigmaRule {
    title: String,
    id: Option<String>,
    status: Option<String>,
    description: Option<String>,
    references: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    authors: Option<String>,
    date: Option<String>,
    logsource: Logsource,
    detections: Option<Vec<Detection>>,
    fields: Option<Vec<String>>,
    falsepositives: Option<Vec<String>>,
    level: Option<String>,
}

impl SigmaRule {

    // When parsing the de yml mapping, think of this nested logic
    // fn is_map() {}
    //     fn contains_list() {}
    //     fn contains_string(){}

    // This adds all of the rules in the config/rules folder upon initialization
    pub fn add_rules() -> Result<(), Error> {
        for file in WalkDir::new("config/rules").into_iter().filter_map(|file| file.ok()) {
            if file.metadata().unwrap().is_file() && is_yml(&file) {

                let de_yml = deserialize_yml(file.path().display().to_string())?;
                let yml_value = Value::deserialize(de_yml)?;

                println!("{:?}", yml_value.is_mapping());
                if let true = yml_value.is_mapping() {
                    let sigmaRule = SigmaRule::build_sigma_rule(&yml_value);
                } else {
                    continue;
                }


            }
        }
        Ok(())
    }

    fn build_sigma_rule(yml_value: &Value) -> Result<(), Error> {
        // dbg!("okok = {:?}", yml_mapping.get("logsource")?.get("service")?.as_str());

        dbg!("SDLK");
        let yml_mapping = yml_value.as_mapping().unwrap();
        println!("N = {:?}", yml_mapping);

        // println!("OK = {:?}", yml_mapping.get("logsource")?);
        // println!("bool = {:?}", yml_mapping.get("logsource")?.is_mapping());

        // let b = if let Some(b) = ... { b } else { ... };
        // let logsource = yml_mapping.get("logsource")?;
        // let category = logsource.get("category").unwrap_or(&Value::Null);
        // let service = logsource.get("service").unwrap_or(&Value::Null);
        // println!("OMG = {:?}", category.as_str());
        // if let false = category.is_null() {category.as_str()?.to_string()};

        // println!("OKDS = {:?}", service.as_str());
        // println!("NICE = {:?}", category.as_str());

        // let logsource = Logsource {
        //     category: Some(yml_mapping.get("logsource")?.get("category")?.as_str()?.to_string()),
        //     service: Some("".to_string()),
        //     product: Some(yml_mapping.get("logsource")?.get("product")?.as_str()?.to_string()),
        // };

        // let rule = SigmaRule {
        //     title: {
        //         yml_mapping.get("title")?.as_str()?.to_string()
        //     },
        //     id: Some(yml_mapping.get("id")?.as_str()?.to_string()),
        //     status: Some(yml_mapping.get("status")?.as_str()?.to_string()),
        //     description: Some("".to_string()),
        //     references: Some(vec![]),
        //     tags: Some(vec![]),
        //     authors: Some("".to_string()),
        //     date: Some("".to_string()),
        //     logsource,
        //     detections: Default::default(),
        //     fields: Some(vec![]),
        //     falsepositives: Some(vec![]),
        //     level: Some("".to_string()),
        // };

        // println!("rule = {:?}", rule);
        Ok(())
    }

    fn is_none(field: Option<&Value>) -> bool {

        if field.is_none() {
            false
        } else {
            true
        }

    }

}

#[cfg(test)]
mod tests {
    use super::*;


}
