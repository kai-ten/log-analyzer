use crate::detection::{Condition, OPERATOR, PARSER_TYPES};
use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::error::{Error, ErrorKind, ParseError};
use nom::IResult;
use crate::parsers::not_parser::not_parser;
use crate::parsers::parens_parser::parens_parser;
use crate::parsers::parser_output::ParserOutput;
use crate::parsers::search_id_parser::search_identifiers_parser;


pub fn and_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut condition = Condition::new();
    let (remaining, result) = and(input)?;

    let mut parser_result = vec![result.to_string()];
    condition.parser_type = Some(PARSER_TYPES::AND);
    condition.parser_result = Some(vec![result.to_string()]);
    condition.operator = Some(OPERATOR::AND);

    let and_parser_result = downstream_and_parser(remaining);
    let mut rule_condition: String = String::new();
    match and_parser_result {
        Ok((_, condition_input)) => {
            let downstream_parser_result = condition_input.parser_result.as_ref().unwrap();
            parser_result.extend(downstream_parser_result.to_vec());
            condition.parser_result = Some(parser_result);
            condition.search_identifier = condition_input.search_identifier.clone();
            condition.nested_detections = condition_input.nested_detections.clone();
            condition.is_negated = Some(condition_input.is_negated.unwrap_or(false)); // this is awful, refactor

            rule_condition = parser_str_builder(condition.clone().parser_result);
        }
        Err(_) => {}
    }

    value(ParserOutput {input: {condition.clone()}}, tag_no_case(rule_condition.clone().as_str()))(input.trim())
}

pub fn and(input: &str) -> IResult<&str, &str> {
    tag_no_case("and")(input.trim())
}

fn downstream_and_parser(input: &str) -> IResult<&str, ParserOutput<Condition>> {
    let result = alt((
        parens_parser,
        not_parser,
        search_identifiers_parser,
    ))(input);

    result
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
    fn and_parser_condition() {
        let result = and_parser("and not filter");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                input: Condition {
                    parser_type: Some(PARSER_TYPES::AND),
                    parser_result: Some(["and".to_string(), "not".to_string(), "filter".to_string()].to_vec()),
                    is_negated: Some(true),
                    operator: Some(OPERATOR::AND),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
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
}
