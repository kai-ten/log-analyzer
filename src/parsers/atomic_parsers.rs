use std::collections::BTreeMap;
use crate::detection::{Condition, OPERATOR};
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
use crate::parsers::input::ConditionInput;
use crate::parsers::operator_parsers::Span;

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

/// TODO: Support wild card names - handled in Detection creation?
/// Returns search identifiers within a condition (take_until(" ")), and at the end of a condition (rest of string)
/// Returns the remaining string to parse, the result that was parsed, and the condition being updated.
/// A successful response indicates that the condition is completed and ready to be stored in a Detection struct
/// A failure indicates invalid input, or potentially a missed parsing use-case.
pub fn search_identifiers(
    input: &str
) -> IResult<&str, &str> {
    let sid = alt((take_until(" "), rest))(input.trim());

    let sid_result = match sid {
        Ok(parsed_sid) => parsed_sid,
        Err(e) => return Err(e),
    };

    Ok((sid_result))
}




pub fn search_identifiers_practice(
    input: &str
) -> IResult<&str, ConditionInput<Condition>> {
    let mut condition = Condition::new();
    let result = search_identifiers(input)?;

    condition.parser_result = Some(vec![result.1.to_string()]);
    condition.search_identifier = Some(result.1.to_string());
    value(ConditionInput { input: { condition.clone() } }, (take_while(|ch| ch != ' ')))(input.trim())
}

pub fn not_practice(
    input: &str
) -> IResult<&str, ConditionInput<Condition>> {

    let mut condition = Condition::new();
    let result = and(input)?;

    condition.parser_result = Some(vec![result.1.to_string()]);
    condition.operator = Some(OPERATOR::AND);
    value(ConditionInput {input: {condition.clone()}}, tag_no_case("and") )(input.trim())
}


pub fn and_practice(
    input: &str
) -> IResult<&str, ConditionInput<Condition>> {

    let mut condition = Condition::new();
    let result = and(input)?;

    condition.parser_result = Some(vec![result.1.to_string()]);
    condition.operator = Some(OPERATOR::AND);
    value(ConditionInput {input: {condition.clone()}}, tag_no_case("and") )(input.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_rule::DetectionTypes::String;
    use log::error;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};

    #[test]
    fn and_test_d() {
        let result = and_practice("and not filter");
        assert_eq!(result, Ok((
            " not filter",
            ConditionInput {
                input: Condition {
                    parser_result: Some(vec!["and".to_string()]),
                    is_negated: None,
                    operator: Some(OPERATOR::AND),
                    search_identifier: None,
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn search_identifier_fun() {


        let result = search_identifiers_practice("Selection");
        assert_eq!(result, Ok((
            "",
            ConditionInput {
                input: Condition {
                    parser_result: Some(vec!["Selection".to_string()]),
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("Selection".to_string()),
                    nested_detections: None
                }
            }
        )));

        let result = search_identifiers_practice("Selection and not Filter");
        assert_eq!(result, Ok((
            " and not Filter",
            ConditionInput {
                input: Condition {
                    parser_result: Some(vec!["Selection".to_string()]),
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("Selection".to_string()),
                    nested_detections: None
                }
            }
        )));

        let result = search_identifiers_practice("");
        assert_eq!(result, Ok((
            "",
            ConditionInput {
                input: Condition {
                    parser_result: Some(vec!["".to_string()]),
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

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

        let end_of_condition_parser_result = search_identifiers(" Events ");
        assert_eq!(end_of_condition_parser_result, Ok(("", "Events")));

        let empty_string_parser_result = search_identifiers("");
        assert_eq!(
            empty_string_parser_result,
            Ok(("", ""))
        );

        let empty_string_parser_result = search_identifiers("    ");
        assert_eq!(empty_string_parser_result, Ok(("", "")));
    }
}
