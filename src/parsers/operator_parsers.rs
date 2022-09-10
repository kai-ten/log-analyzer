use crate::detection::Condition;
use crate::parsers::atomic_parsers::{
    all_of, all_of_them, and, not, one_of, one_of_them, or, parens, pipe, search_identifiers,
};
use log::warn;
use nom::branch::alt;
use nom::error::ErrorKind::Tag;
use nom::error::{Error, ErrorKind, ParseError};
use nom::{error_position, Finish, IResult};
use std::borrow::BorrowMut;

/// Parser when parens is a match
///
/// The below links contains a reference to the library that fixes this issue. Nom will support in v8.0
/// https://stackoverflow.com/questions/70630556/parse-allowing-nested-parentheses-in-nom
pub fn parser(input: &str) -> IResult<&str, &str> {
    let result: IResult<&str, &str> = alt((
        parens,
        one_of_them,
        all_of_them,
        one_of,
        all_of,
        not,
        and,
        or,
        pipe,
        search_identifiers,
    ))(input);

    result
}

/// Parser when not is a match
pub fn not_parser(input: &str) -> Result<(&str, &str, Condition), Error<&str>> {
    let result: Result<(&str, &str), Error<&str>> =
        alt((parens, search_identifiers))(input).finish();

    let mut condition = Condition::new();

    // udpate here

    let ok2 = match result {
        Ok(wow) => wow,
        Err(e) => return Err(e),
    };

    Ok((ok2.0, ok2.1, condition))
}

/// Parser when operator is a match
pub fn conditional_parser(input: &str) -> IResult<&str, &str> {
    let result: IResult<&str, &str> = alt((parens, not, search_identifiers))(input);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_rule::DetectionTypes::String;
    use log::error;
    use nom::error::ErrorKind::Tag;

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
    fn parser_returns_ok_response_for_all_condition_specs() {
        // write tests in this exact location
    }

    #[test]
    fn not_parser_valid_inputs() {
        let condition = Condition::new();

        let parens_parser_result = not_parser("(not keywords) or filters");
        println!("{:?}", parens_parser_result);
        assert_eq!(
            parens_parser_result,
            Ok((" or filters", "not keywords", condition))
        );

        let condition2 = Condition::new();

        let search_id_parser_result = not_parser("keywords");
        println!("{:?}", search_id_parser_result);
        assert_eq!(search_id_parser_result, Ok(("", "keywords", condition2)));
    }

    #[test]
    fn operator_parser_valid_inputs() {
        let parens_parser_result = conditional_parser("(not keywords) or filters");
        assert_eq!(parens_parser_result, Ok((" or filters", "not keywords")));

        let not_parser_result = conditional_parser("not keywords");
        assert_eq!(not_parser_result, Ok((" keywords", "not")));

        let search_id_parser_result = conditional_parser("keywords");
        assert_eq!(search_id_parser_result, Ok(("", "keywords")));
    }
}
