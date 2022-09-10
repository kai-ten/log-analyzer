use crate::detection::Condition;
use crate::parsers::take_until_unbalanced::take_until_unbalanced;
use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, tag_no_case, take_until};
use nom::character::complete::none_of;
use nom::character::{is_alphabetic, is_alphanumeric};
use nom::combinator::rest;
use nom::error::ErrorKind::{Char, Tag};
use nom::error::{Error, ErrorKind, ParseError};
use nom::multi::many0;
use nom::sequence::delimited;
use nom::{Finish, IResult};

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

pub fn not(input: &str) -> IResult<&str, &str> {
    tag_no_case("not")(input.trim())
}

pub fn or(input: &str) -> IResult<&str, &str> {
    tag_no_case("or")(input.trim())
}

pub fn and(input: &str) -> IResult<&str, &str> {
    tag_no_case("and")(input.trim())
}

pub fn pipe(input: &str) -> IResult<&str, &str> {
    tag_no_case("|")(input.trim())
}

/// Returns search identifiers within a condition (take_until(" ")), and at the end of a condition (rest of string)
/// TODO: Support wild card names - handled in Detection creation?
pub fn search_identifiers(
    input: &str,
    condition: Condition,
) -> Result<(&str, &str, Condition), Error<&str>> {
    let condition: Condition = condition;
    let sid: Result<(&str, &str), E> = alt((take_until(" "), rest))(input.trim()).finish();

    match sid {
        Ok(parsed_sid) => parsed_sid,
        Err(e) => return Err(e),
    }

    Ok((ok2.0, ok2.1, condition))
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

    #[test]
    fn one_of_them_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    #[test]
    fn all_of_them_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    #[test]
    fn one_of_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    #[test]
    fn all_of_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    ///////////////////////////////
    ///////////////////////////////
    ///////////////////////////////

    #[test]
    fn not_input() {
        let parser_result = not(" not events ");
        assert_eq!(parser_result, Ok((" events", "not")));

        let parser_result = not(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    #[test]
    fn or_input() {
        let parser_result = or(" or events ");
        assert_eq!(parser_result, Ok((" events", "or")));

        let parser_result = or(" and events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
        );
    }

    #[test]
    fn and_input() {
        let parser_result = and(" and events ");
        assert_eq!(parser_result, Ok((" events", "and")));

        let parser_result = and(" or events ");
        assert_eq!(
            parser_result,
            Err(nom::Err::Error(Error::from_error_kind("or events", Tag)))
        );
    }

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

    #[test]
    fn search_identifiers_input() {
        let mid_condition_parser_result = search_identifiers(" Selection and not Filter ");
        assert_eq!(
            mid_condition_parser_result,
            Ok((" and not Filter", "Selection"))
        );

        let end_of_condition_parser_result = search_identifiers(" Events "); // but that wasn't being supported with only the first match
        assert_eq!(end_of_condition_parser_result, Ok(("", "Events")));

        let empty_string_parser_result = search_identifiers(""); // but that wasn't being supported with only the first match
        assert_eq!(
            empty_string_parser_result,
            Err(nom::Err::Error(Error::from_error_kind(
                "Empty string cannot be a search identifier.",
                Char
            )))
        );

        let empty_string_parser_result = search_identifiers("    "); // but that wasn't being supported with only the first match
        assert_eq!(empty_string_parser_result, Ok(("", "")));
    }
}
