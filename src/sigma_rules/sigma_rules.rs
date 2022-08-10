use std::collections::BTreeMap;
use std::io::BufReader;
use serde::{Serialize, Deserialize};
use serde_yaml::{Mapping, Value};
use crate::utils::yml_file::{self, read};

#[derive(Debug)]
enum RequiredFields {
    title,
    logSource,
    detection,
    condition,
}

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

// https://www.reddit.com/r/rust/comments/pv38v0/how_to_allow_optional_fields_in_struct/

impl SigmaRule {

    // fn is_map() {}
    //     fn contains_list() {}
    //     fn contains_string(){}

    // This adds all of the rules in the config/rules folder upon initialization
    fn add_rules() {
        let de_yml = read();
    }

    fn build_sigma_rule(yml_mapping: &Value) -> Option<SigmaRule> {
        dbg!("{:?}", yml_mapping);

        // dbg!("okok = {:?}", yml_mapping.get("logsource")?.get("service")?.as_str());

        dbg!("SDLK");
        let nice = yml_mapping.get("logsource")?.get("service");
        // if let true = nice.is_none() {
        //     println!("WOOO");
        // } else {
        //     println!("NOOO");
        // }


        // dbg!("THIS = {:?}", nice);


        let logsource = Logsource {
            category: Some(yml_mapping.get("logsource")?.get("category")?.as_str()?.to_string()),
            service: Some("".to_string()),
            product: Some(yml_mapping.get("logsource")?.get("product")?.as_str()?.to_string()),
        };

        let rule = SigmaRule {
            title: {
                yml_mapping.get("title")?.as_str()?.to_string()
            },
            id: Some(yml_mapping.get("id")?.as_str()?.to_string()),
            status: Some(yml_mapping.get("status")?.as_str()?.to_string()),
            description: Some("".to_string()),
            references: Some(vec![]),
            tags: Some(vec![]),
            authors: Some("".to_string()),
            date: Some("".to_string()),
            logsource,
            detections: Default::default(),
            fields: Some(vec![]),
            falsepositives: Some(vec![]),
            level: Some("".to_string()),
        };

        println!("rule = {:?}", rule);
        Some(rule)
    }

    fn is_none() -> bool {


        return false;
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_yml_as_string() {
        let test = Nice();

        // println!("{:?}", test);
        // println!("{}", test.title)
        // Ok(_) => assert!(false, "db file should not exist"),
        // Err(read_yaml()) => assert!(true),

        // assert_eq!((), read_yaml().unwrap());
    }
}
