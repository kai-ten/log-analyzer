use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;

use crate::parens_parser::parens_parser;
use crate::search_id_parser::search_identifiers_parser;
use crate::parser_output::ParserOutput;
use crate::structs::condition::{Condition, PARSER_TYPES};


pub fn not_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut condition = Condition::new();
    let (remaining, result) = not(input)?;

    let mut parser_result = vec![result.to_string()];
    condition.parser_type = Some(PARSER_TYPES::NOT);
    condition.is_negated = Some(true);


    let not_parser_result = downstream_not_parser(remaining);
    let mut rule_condition = String::new();
    match not_parser_result {
        Ok((_, condition_input)) => {
            let downstream_parser_result = condition_input.parser_result.as_ref().unwrap();
            parser_result.extend(downstream_parser_result.to_vec());
            condition.parser_result = Some(parser_result);
            condition.search_identifier = condition_input.search_identifier.clone();
            condition.nested_detections = condition_input.nested_detections.clone();

            rule_condition = parser_str_builder(condition.clone().parser_result);
        }
        Err(_) => {}
    }

    value(ParserOutput {input: {condition.clone()}}, tag_no_case(rule_condition.clone().as_str()))(input.trim())
}

fn not(input: &str) -> IResult<&str, &str> {
    tag_no_case("not")(input.trim())
}

fn downstream_not_parser(input: &str) -> IResult<&str, ParserOutput<Condition>> {

    let result = alt((
        parens_parser,
        // one of / all of combos
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
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};

    #[test]
    fn not_parser_condition() {
        let result = not_parser("not filter");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                input: Condition {
                    parser_type: Some(PARSER_TYPES::NOT),
                    parser_result: Some(["not".to_string(), "filter".to_string()].to_vec()),
                    is_negated: Some(true),
                    operator: None,
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

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
}
