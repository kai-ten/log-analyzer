use std::collections::BTreeMap;
use crate::structs::detection_logic::DetectionLogic;
use crate::structs::sigma_rule::YmlTypes;

pub fn parse_search_identifier(logic: YmlTypes) -> DetectionLogic {

    let mut detection_logic = DetectionLogic::init();

    match logic {
        YmlTypes::Mapping(search_id) => {
            let logic = search_id.as_ref().unwrap();
            let mut nested_detection_logic = DetectionLogic::init();

            for (field, detection_logic_yml) in logic.clone() {
                let detection_field = field;
                nested_detection_logic = parse_search_identifier(detection_logic_yml);

                let mut mapping_logic = BTreeMap::new();
                mapping_logic.insert(detection_field, nested_detection_logic);
                detection_logic.and = Some(mapping_logic);
            }

            return detection_logic;
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
            return detection_logic;
        },
        YmlTypes::Boolean(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id.to_string());

            return nested_detection_logic;
        },
        YmlTypes::Number(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id.to_string());

            return nested_detection_logic;
        },
        YmlTypes::String(search_id) => {
            let mut nested_detection_logic = DetectionLogic::init();
            nested_detection_logic.value = Some(search_id);

            return nested_detection_logic;
        },
    };
}


#[cfg(test)]
mod tests {
    use crate::detection_parsers::logic_parser::parse_search_identifier;
    use crate::sigma_file::sigma_rule::process_sigma_rules;

    #[test]

    fn read_condition_sequence_type() {
        let rules = process_sigma_rules("src/sigma_file/test/assets/mimikatz.yml".to_string()).unwrap();
        println!("Rules: {:?}", rules);

        for rule in rules {
            for (search_identifier, detection) in rule.detection {
                let result = parse_search_identifier(detection);
                println!("Result: {:?}", result);
            }
        }
    }

}
