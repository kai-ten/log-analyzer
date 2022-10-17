use std::collections::BTreeMap;
use crate::structs::detection_logic::DetectionLogic;
use crate::structs::sigma_rule::YmlTypes;


pub fn parse_search_identifier(logic: YmlTypes) -> DetectionLogic {
    let mut detection_logic = DetectionLogic::init();

    return match logic {
        YmlTypes::Mapping(search_id) => {
            let logic = search_id;
            let mut nested_detection_logic = DetectionLogic::init();

            let mut mapping_logic = BTreeMap::new();

            for (field, detection_logic_yml) in logic.clone() {
                let detection_field = field;
                nested_detection_logic = parse_search_identifier(detection_logic_yml);

                mapping_logic.insert(detection_field, nested_detection_logic);
            }
            detection_logic.and = Some(mapping_logic);
            detection_logic
        },
        YmlTypes::Sequence(search_id) => {
            let logic = search_id.to_vec();
            let mut sequence_logic: Vec<DetectionLogic> = Vec::new();
            let mut nested_detection_logic = DetectionLogic::init();

            for detection_logic_yml in logic {
                nested_detection_logic = parse_search_identifier(detection_logic_yml);
                sequence_logic.push(nested_detection_logic);
            }

            detection_logic.or = Some(sequence_logic);
            detection_logic
        },
        YmlTypes::Boolean(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id.to_string());

            nested_detection_logic
        },
        YmlTypes::Number(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id.to_string());

            nested_detection_logic
        },
        YmlTypes::String(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id);

            nested_detection_logic
        },
        _ => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some("".to_string());

            nested_detection_logic
        }
    };
}


#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::detection_parsers::logic::logic_parser::parse_search_identifier;
    use crate::sigma_file::sigma_rule::process_sigma_rules;
    use crate::structs::detection_logic::DetectionLogic;
    use crate::structs::sigma_rule::{Logsource, SigmaRule, YmlTypes::Sequence, YmlTypes::Number, YmlTypes::Mapping};


    // TODO: Refactor this test to not use a file
    #[test]
    fn parse_mapping_logic() {
        let rules = process_sigma_rules("src/sigma_file/test/assets/detection_logic/mapping.yml".to_string()).unwrap();

        for rule in rules {
            for (search_identifier, detection) in rule.detection.clone() {
                let result = parse_search_identifier(detection);

                let mut mapping = BTreeMap::new();
                mapping.insert("EventID".to_string(), DetectionLogic {
                    and: None,
                    or: Some(vec![
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("456".to_string())
                        },
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("876".to_string())
                        }
                    ]),
                    value: None
                });

                mapping.insert("ComputerName".to_string(), DetectionLogic {
                    and: None,
                    or: Some(vec![
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("dc1".to_string())
                        },
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("dc2".to_string())
                        }
                    ]),
                    value: None
                });

                let detection_logic = DetectionLogic {
                    and: Some(mapping),
                    or: None,
                    value: None
                };

                assert_eq!(result, detection_logic);
            }
        }
    }

    // TODO: Refactor this test to not use a file
    #[test]
    fn parse_sequence_logic() {
        let rules = process_sigma_rules("src/sigma_file/test/assets/detection_logic/sequence.yml".to_string()).unwrap();

        for rule in rules {
            for (search_identifier, detection) in rule.detection {
                let result = parse_search_identifier(detection);

                assert_eq!(result, DetectionLogic {
                    and: None,
                    or: Some(vec![
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("456".to_string())
                        },
                        DetectionLogic {
                            and: None,
                            or: None,
                            value: Some("876".to_string())
                        }
                    ]),
                    value: None
                });
            }
        }
    }

}
