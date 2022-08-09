use std::collections::BTreeMap;
use std::io::BufReader;
use serde::{Serialize, Deserialize};
use serde_yaml::{Mapping, Value};

// #[derive(Debug)]
// enum DetectionType<T> {
//     Int(i64),
//     Float(f64),
//     String(String),
//     Boolean(bool),
//     DetectionMap(HashMap<T, T>),
//     DetectionList(Vec<T>),
//     None,
// }

#[derive(Debug)]
enum SigmaOption<T> {
    Some(T),
    None,
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

    pub fn read_yml() -> Result<(), Box<dyn std::error::Error>> {

        let file = std::fs::File::open("test/assets/proc_access_win_mimikatz_through_winrm.yml")?;
        let buf_reader = BufReader::new(file);
        let de_yml = serde_yaml::Deserializer::from_reader(buf_reader);
        let yml_mapping = Value::deserialize(de_yml)?;

        if yml_mapping.is_mapping() {
            // println!("YES! ITS MAPPING = {:?}", yml_mapping);
            let ok = SigmaRule::build_sigma_rule(&yml_mapping);
        } else {
            // Return exception and continue
        }

        Ok(())
    }

    fn build_sigma_rule(yml_mapping: &Value) -> Option<SigmaRule> {
        dbg!("{:?}", yml_mapping);

        // dbg!("okok = {:?}", yml_mapping.get("logsource")?.get("service")?.as_str());

        let okok:SigmaOption<String> = SigmaOption::Some(yml_mapping.get("logsource")?.get("service")?.as_str()?.to_string());
        dbg!("THIS = {:?}", okok);


        let logsource = Logsource {
            category: Some(yml_mapping.get("logsource")?.get("category")?.as_str()?.to_string()),
            service: Some(yml_mapping.get("logsource")?.get("service")?.as_str()?.to_string()),
            product: Some(yml_mapping.get("logsource")?.get("product")?.as_str()?.to_string()),
        };

        let rule = SigmaRule {
            title: yml_mapping.get("title")?.as_str()?.to_string(),
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
            level: Some("".to_string())
        };

        println!("rule = {:?}", rule);
        Some(rule)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_yml_as_string() {
        let test = SigmaRule::read_yml().unwrap();

        // println!("{:?}", test);
        // println!("{}", test.title)
        // Ok(_) => assert!(false, "db file should not exist"),
        // Err(read_yaml()) => assert!(true),

        // assert_eq!((), read_yaml().unwrap());
    }
}
