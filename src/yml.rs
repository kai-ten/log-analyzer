use std::fs::File;
use std::io::BufReader;
use serde_yaml::Deserializer;

pub fn deserialize_yml<'de>(path: String) -> std::io::Result<Deserializer<'de>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let de_yml = Deserializer::from_reader(reader);
    Ok(de_yml)
}

#[cfg(test)]
mod test_yml_deserialization {
    use super::*;

    #[test]
    fn test_de_yml() {
        let yaml = deserialize_yml("test/assets/simple.yml".to_string());
        assert_eq!(yaml.is_ok(), true, "Yml returns as a mapping")
    }

    #[test]
    fn de_yml_file_that_does_not_exist() {
        let yaml = deserialize_yml("test/assets/should_not_exist.yml".to_string());
        assert_eq!(yaml.is_err(), true, "File does not exist")
    }
}


