use std::io::BufReader;
use serde::Deserialize;
use serde_yaml::Value;

pub fn read() -> Result<Value, serde_yaml::Error> {
    let file = std::fs::File::open("test/assets/proc_access_win_mimikatz_through_winrm.yml")?;
    let buf_reader = BufReader::new(file);
    let de_yml = serde_yaml::Deserializer::from_reader(buf_reader);

    Value::deserialize(de_yml)
}
