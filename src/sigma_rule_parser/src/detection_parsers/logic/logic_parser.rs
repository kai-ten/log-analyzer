use std::collections::BTreeMap;
use std::fmt::Error;
use crate::structs::detection::Detection;
use crate::structs::detection_condition::{DetectionCondition, Operator};
use crate::structs::detection_logic::DetectionLogic;
use crate::structs::sigma_rule::YmlTypes;

/// Business logic:
/// At the root level of a Detection struct, the operator determines whether there is more to process or not.
///     - If None, the condition is a single phrase (i.e. "selection" or "(selection and keywords)"
///     - If Some, the condition is a chain of events
/// The DetectionCondition struct actually forms the '''first order logic''' in the detection of a Sigma rule
///     - The condition field is special in that it governs relationships between subsets of logic
/// The DetectionLogic field is what creates these so-called 'subsets of logic', a.k.a. '''second order logic'''
///     - The Search Identifier is a unique name that identifies the logic to perform on the data that is being compared to
/// By assigning DetectionLogic within a DetectionCondition struct, the condition is able to govern the higher order relationships with the logic that must be calculated
pub fn parse_detection_logic(parsed_detection: &mut Detection, sigma_detection: BTreeMap<String, YmlTypes>) -> Result<&Detection, Error> {

    println!("0 - {:?}", parsed_detection.clone());
    println!("1 - {:?}", sigma_detection.clone());

    let mut detection_condition = DetectionCondition::init();

    match parsed_detection.operator {
        None => {
            // check to see if nested_detection or search_id is not None
            // TODO: Can I get rid of this for loop since there is no operator? AKA get rid of this soon.
            for condition in parsed_detection.conditions.as_ref().unwrap() {
                println!("Nice - {:?}", condition.clone());
                if condition.nested_detections.is_some() {
                    println!("ON THE WAY");
                } else if condition.search_identifier.is_some() {

                    detection_condition = condition.clone();

                    // for loop of sigma_detection that has if statement and if true then assign logic to value outside of loop and break loop
                    println!("parsed - {:?}", parsed_detection);
                    println!("sigma - {:?}", sigma_detection);
                    for (search_id, logic) in sigma_detection.clone() {
                        if condition.search_identifier.as_ref().unwrap() == &search_id {
                            println!("yay");
                            let parsed_logic = parse_search_identifier(logic);
                            println!("{:?}", parsed_logic);
                            detection_condition.detection_logic = parsed_logic;
                        } else {
                            println!("nay");
                        }
                    }
                } else {

                }
            }
        }
        Some(_) => {
            // figure out order of operations to parse through possible paths recursively
        }
    };

    parsed_detection.conditions = Some(vec![detection_condition]);
    Ok(parsed_detection)
}

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
