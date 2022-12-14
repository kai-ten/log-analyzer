use walkdir::DirEntry;

pub fn is_yml(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.ends_with(".yml") || s.ends_with(".yaml"))
        .unwrap_or(false)
}

#[cfg(test)]
mod test_yml_deserialization {
    use super::*;
    use walkdir::WalkDir;

    #[test]
    fn is_yml_file() {
        for file in WalkDir::new("test/assets/mimikatz.yml")
            .into_iter()
            .filter_map(|file| file.ok())
        {
            let is_yml = is_yml(&file);
            assert_eq!(is_yml, true, "Is a yml file")
        }
    }

    #[test]
    fn is_yaml_file() {
        for file in WalkDir::new("test/assets/mimikatz.yaml")
            .into_iter()
            .filter_map(|file| file.ok())
        {
            let is_yml = is_yml(&file);
            assert_eq!(is_yml, true, "Is a yml file")
        }
    }

    #[test]
    fn is_not_yml_file() {
        for file in WalkDir::new("test/assets/is_not_yml_file/not_yml.txt")
            .into_iter()
            .filter_map(|file| file.ok())
        {
            let is_yml = is_yml(&file);
            assert_eq!(is_yml, false, "Is not a yml file")
        }
    }
}
