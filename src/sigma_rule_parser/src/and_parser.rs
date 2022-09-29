use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;
use crate::not_parser::not_parser;
use crate::parens_parser::parens_parser;

use crate::parser_output::ParserOutput;
use crate::search_id_parser::search_identifiers_parser;
use crate::structs::condition::{Condition, Metadata, OPERATOR, PARSER_TYPES};


pub fn and_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {
    let mut condition = Condition::init();

    let (remaining, result) = and(input)?;
    let mut result_condition: String = String::from(result);

    let and_parser_result = downstream_and_parser(remaining.trim());
    match and_parser_result {
        Ok((_, parser_output)) => {
            let downstream_parser_result = parser_output.metadata.parser_result.clone();
            result_condition = format!("{}{}{}", result_condition, " ", remaining.trim());

            println!("{:?}", result_condition);

            let metadata = Metadata::new(
                PARSER_TYPES::AND,
                result_condition.clone()
            );

            condition = Condition::new(
                metadata,
                Some(parser_output.is_negated.unwrap_or(false)),
                Some(OPERATOR::AND),
                parser_output.search_identifier.clone(),
                parser_output.nested_detections.clone()
            );
        }
        Err(_) => {}
    }

    value(ParserOutput { result: {condition.clone()}}, tag_no_case(result_condition.clone().as_str()))(input.trim())
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


#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::structs::condition::Metadata;
    use crate::structs::detection::Detection;

    #[test]
    fn and_parens_parser_condition() {
        let result = and_parser("and (filter or not selection)");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::AND,
                        parser_result: "and (filter or not selection)".to_string(),
                    },
                    is_negated: Some(false),
                    operator: Some(OPERATOR::AND),
                    search_identifier: None,
                    nested_detections: Some(Detection {
                        operator: Some(OPERATOR::OR),
                        conditions: Some(vec![
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                                    parser_result: "filter".to_string()
                                },
                                is_negated: None,
                                operator: None,
                                search_identifier: Some("filter".to_string()),
                                nested_detections: None
                            },
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::OR,
                                    parser_result: "or not selection".to_string()
                                },
                                is_negated: Some(true),
                                operator: Some(OPERATOR::OR),
                                search_identifier: Some("selection".to_string()),
                                nested_detections: None
                            }
                        ])
                    })
                }
            }
        )));
    }

    #[test]
    fn and_not_parser_condition() {
        let result = and_parser("and not filter");

        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::AND,
                        parser_result: "and not filter".to_string(),
                    },
                    is_negated: Some(true),
                    operator: Some(OPERATOR::AND),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn and_parser_condition() {
        let result = and_parser("and filter");

        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::AND,
                        parser_result: "and filter".to_string(),
                    },
                    is_negated: Some(false),
                    operator: Some(OPERATOR::AND),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn and_parens_input() {
        let parser_result = and(" and (events or selection) ");
        assert_eq!(parser_result, Ok((" (events or selection)", "and")));
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