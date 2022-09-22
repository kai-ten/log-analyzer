use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;

use log_analyzer::detection::{Condition, OPERATOR, PARSER_TYPES};

use sigma_rule_parser::not_parser::not_parser;
use sigma_rule_parser::parens_parser::parens_parser;
use sigma_rule_parser::parser_output::ParserOutput;
use sigma_rule_parser::search_id_parser::search_identifiers_parser;
use crate::not_parser::not_parser;
use crate::parens_parser::parens_parser;
use crate::parser_output::ParserOutput;
use crate::search_id_parser::search_identifiers_parser;


pub fn or_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut condition = Condition::new();
    let (remaining, result) = or(input)?;

    let mut parser_result = vec![result.to_string()];
    condition.parser_type = Some(PARSER_TYPES::OR);
    condition.parser_result = Some(vec![result.to_string()]);
    condition.operator = Some(OPERATOR::OR);

    let or_parser_result = downstream_or_parser(remaining);
    let mut rule_condition: String = String::new();
    match or_parser_result {
        Ok((_, condition_input)) => {
            let downstream_parser_result = condition_input.parser_result.as_ref().unwrap();
            parser_result.extend(downstream_parser_result.to_vec());
            condition.parser_result = Some(parser_result);
            condition.search_identifier = condition_input.search_identifier.clone();
            condition.nested_detections = condition_input.nested_detections.clone();
            condition.is_negated = Some(condition_input.is_negated.unwrap_or(false));

            rule_condition = parser_str_builder(condition.clone().parser_result);
        }
        Err(_) => {}
    }

    value(ParserOutput {input: {condition.clone()}}, tag_no_case(rule_condition.clone().as_str()))(input.trim())
}

fn or(input: &str) -> IResult<&str, &str> {
    tag_no_case("or")(input.trim())
}

pub fn downstream_or_parser(input: &str) -> IResult<&str, ParserOutput<Condition>> {

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
    use log_analyzer::sigma_rule::DetectionTypes::String;
    use log::error;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};

    #[test]
    fn or_parser_condition() {
        let result = or_parser("or not filter");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                input: Condition {
                    parser_type: Some(PARSER_TYPES::OR),
                    parser_result: Some(["or".to_string(), "not".to_string(), "filter".to_string()].to_vec()),
                    is_negated: Some(true),
                    operator: Some(OPERATOR::OR),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
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
}