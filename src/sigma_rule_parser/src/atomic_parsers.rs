use std::borrow::Borrow;
use std::collections::BTreeMap;

use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, tag_no_case, take_until, take_while};
use nom::character::complete::none_of;
use nom::character::{is_alphabetic, is_alphanumeric};
use nom::combinator::{rest, value};
use nom::error::ErrorKind::{Char, Tag};
use nom::error::{Error, ErrorKind, ParseError};
use nom::multi::many0;
use nom::sequence::delimited;
use nom::{AsBytes, Finish, InputLength, InputTake, IResult, Parser};

use log_analyzer::detection::{Condition, Detection, OPERATOR, parse_detection, PARSER_TYPES};

use sigma_rule_parser::take_until_unbalanced::take_until_unbalanced;
use sigma_rule_parser::not_parser::not_parser;
use sigma_rule_parser::operator_parsers::parser;
use sigma_rule_parser::parser_output::ParserOutput;

pub fn one_of_them(input: &str) -> IResult<&str, &str> {
    tag_no_case("1 of them")(input.trim())
}

pub fn all_of_them(input: &str) -> IResult<&str, &str> {
    tag_no_case("all of them")(input.trim())
}

pub fn one_of(input: &str) -> IResult<&str, &str> {
    tag_no_case("1 of")(input.trim())
}

pub fn all_of(input: &str) -> IResult<&str, &str> {
    tag_no_case("all of")(input.trim())
}

pub fn pipe(input: &str) -> IResult<&str, &str> {
    tag_no_case("|")(input.trim())
}



fn parser_str_builder(input: Option<Vec<String>>) -> String {
    input.as_ref().unwrap().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use log_analyzer::sigma_rule::DetectionTypes::String;
    use log::error;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};


    // Do this stuff eventually
    ///////////////////////////////
    ///////////////////////////////
    ///////////////////////////////

    // #[test]
    // fn one_of_them_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn all_of_them_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn one_of_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn all_of_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }

    ///////////////////////////////
    ///////////////////////////////
    ///////////////////////////////

    #[test]
    fn pipe_input() {
        let parser_result = pipe(" | countBy() events > 10 ");
        assert_eq!(parser_result, Ok((" countBy() events > 10", "|")));

        let parser_result = pipe(" or events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("or events", Tag)))
        );
    }
}
