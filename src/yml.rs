use std::fs::File;
use std::io::BufReader;
use serde_yaml::Deserializer;
use walkdir::DirEntry;

pub fn deserialize_yml<'de>(path: String) -> std::io::Result<Deserializer<'de>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let de_yml = Deserializer::from_reader(reader);
    Ok(de_yml)
}

pub fn is_yml(entry: &DirEntry) -> bool {
    entry.file_name()
        .to_str()
        .map(|s| s.ends_with(".yml"))
        .unwrap_or(false)
}

#[cfg(test)]
mod test_yml_deserialization {
    use walkdir::WalkDir;
    use super::*;

    // #[test]
    // fn test_de_yml() {
    //     let yaml = deserialize_yml("test/assets/simple.yml".to_string());
    //     assert_eq!(yaml.is_ok(), true, "Yml returns as a mapping")
    // }
    //
    // #[test]
    // fn de_yml_file_that_does_not_exist() {
    //     let yaml = deserialize_yml("test/assets/should_not_exist.yml".to_string());
    //     assert_eq!(yaml.is_err(), true, "File does not exist")
    // }
    //
    // #[test]
    // fn is_yml_file() {
    //     for file in WalkDir::new("test/assets/simple.yml").into_iter().filter_map(|file| file.ok()) {
    //         let is_yml = is_yml(&file);
    //         assert_eq!(is_yml, true, "Is a yml file")
    //     };
    // }
    //
    // #[test]
    // fn is_not_yml_file() {
    //     for file in WalkDir::new("test/assets/is_not_yml_file/").into_iter().filter_map(|file| file.ok()) {
    //         let is_yml = is_yml(&file);
    //         assert_eq!(is_yml, false, "Is not a yml file")
    //     };
    // }
}


