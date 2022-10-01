use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct FieldMapping {
    target_field: String,
    source_field: String,
}

pub fn parse_field_mappings() -> Vec<FieldMapping> {
    let mapping_path = Path::new("../../../test/assets/valid_fieldmapping.json");
    println!("Path: {:?}", mapping_path);

    let data = fs::read_to_string(mapping_path).expect("Unable to read file");
    // println!("File data: {:?}", data);

    let json: HashMap<String, String> = serde_json::from_str(&data).expect("Invalid JSON format");
    println!("json: {:?}", json);

    let mut field_mappings: Vec<FieldMapping> = vec![];
    for (target, source) in json {
        field_mappings.push(FieldMapping {
            target_field: target,
            source_field: source,
        })
    }

    field_mappings
}

#[cfg(test)]
mod tests {
    use crate::field_mappings::{parse_field_mappings, FieldMapping};

    #[test]
    fn parse_field_mappings_file() {
        let actual_mapping = parse_field_mappings();
        let expected_mapping = vec![
            FieldMapping {
                target_field: "target-field".to_string(),
                source_field: "json-source-field".to_string(),
            },
            FieldMapping {
                target_field: "TargetImage".to_string(),
                source_field: "target.img".to_string(),
            },
            FieldMapping {
                target_field: "SourceImage".to_string(),
                source_field: "source.img".to_string(),
            },
            FieldMapping {
                target_field: "EventCode".to_string(),
                source_field: "event.code".to_string(),
            },
            FieldMapping {
                target_field: "EventMsg".to_string(),
                source_field: "event.msg".to_string(),
            },
        ];

        assert_eq!(actual_mapping.len(), expected_mapping.len());
    }
}
