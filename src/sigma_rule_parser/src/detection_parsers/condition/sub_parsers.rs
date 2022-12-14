use nom::branch::alt;
use nom::error::Error;
use nom::{Finish, IResult};

use crate::detection_parsers::condition::parser_output::ParserOutput;

use crate::structs::detection_condition::DetectionCondition;
use crate::detection_parsers::condition::and_parser::and_parser;
use crate::detection_parsers::condition::not_parser::not_parser;
use crate::detection_parsers::condition::or_parser::or_parser;
use crate::detection_parsers::condition::parens_parser::parens_parser;
use crate::detection_parsers::condition::search_id_parser::search_identifiers_parser;

/// Parser when parens is a match
/// The below links contains a reference to the library that fixes this issue. Nom will support in v8.0
/// https://stackoverflow.com/questions/70630556/parse-allowing-nested-parentheses-in-nom
pub fn parser(input: &str) -> Result<(&str, ParserOutput<DetectionCondition>), Error<&str>> {
    let result = alt((
        parens_parser,
        not_parser,
        and_parser,
        or_parser,
        search_identifiers_parser,
    ))(input)
    .finish();

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn testa90() {
    //     let rule = SigmaRule {
    //         title: "Startup Items",
    //         id: "dfe8b941-4e54-4242-b674-6b613d521962",
    //         status: "test",
    //         description: "Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.",
    //         references: ["https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.005/T1037.005.md"],
    //         tags: ["attack.persistence", "attack.privilege_escalation", "attack.t1037.005"],
    //         author: "Alejandro Ortuno, oscd.community",
    //         date: "2020/10/14",
    //         modified: "2022/07/11",
    //         logsource: Logsource { category: "file_event", product: "macos", service: "", definition: "" }, related: [],
    //         detection: {
    //              "condition": String("selection"),
    //              "selection": Sequence([Mapping(Some({"TargetFilename|contains": String("/Library/StartupItems/")})), Mapping(Some({"TargetFilename|endswith": String(".plist")}))])}, fields: [], falsepositives: ["Legitimate administration activities"], level: "low" };
    // }

    #[test]
    fn test_parser() {
        let test = parser("Selection");
        println!("{:?}", test);
    }

    #[test]
    fn parser_returns_ok_response_for_all_condition_specs() {
        // write tests in this exact location
    }
}
