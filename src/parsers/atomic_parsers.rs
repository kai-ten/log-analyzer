use std::collections::BTreeMap;
use crate::detection::{Condition, OPERATOR, PARSER_TYPES};
use crate::parsers::take_until_unbalanced::take_until_unbalanced;
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
use crate::parsers::not_parser::not_parser;
use crate::parsers::parser_output::ParserOutput;

pub fn parens(input: &str) -> IResult<&str, &str> {
    delimited(tag("("), take_until_unbalanced('(', ')'), tag(")"))(input.trim())
}

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
    use crate::sigma_rule::DetectionTypes::String;
    use log::error;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};

    #[test]
    fn parens_input_nested() {
        let parser_result =
            parens("((filter1 and filter2) or keywords or events) and not selection");
        assert_eq!(
            parser_result,
            Ok((
                " and not selection",
                "(filter1 and filter2) or keywords or events"
            ))
        );

        let remaining_value = match parser_result {
            Ok((returned, remaining)) => remaining,
            Err(err) => "Error",
        };

        // Test the nested parentheses
        let nested_parser_result = parens(remaining_value);
        assert_eq!(
            nested_parser_result,
            Ok((" or keywords or events", "filter1 and filter2"))
        );

        let parser_result = parens(" keywords and not selection ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind(
                "keywords and not selection",
                Tag
            )))
        );
    }

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
