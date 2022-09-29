use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::combinator::value;
use nom::IResult;

use crate::not_parser::not_parser;
use crate::parens_parser::parens_parser;
use crate::parser_output::ParserOutput;
use crate::search_id_parser::search_identifiers_parser;
use crate::structs::condition::{Condition, Metadata, OPERATOR, PARSER_TYPES};


pub fn or_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut condition = Condition::init();
    let (remaining, result) = or(input)?;
    let mut result_condition: String = String::from(result);

    let or_parser_result = downstream_or_parser(remaining.trim());
    match or_parser_result {
        Ok((_, parser_output)) => {
            let downstream_parser_result = parser_output.metadata.parser_result.clone();
            result_condition = format!("{}{}{}", result_condition, " ", remaining.trim());

            let metadata = Metadata::new(
                PARSER_TYPES::OR,
                result_condition.clone()
            );

            condition = Condition::new(
                metadata,
                Some(parser_output.is_negated.unwrap_or(false)),
                Some(OPERATOR::OR),
                parser_output.search_identifier.clone(),
                parser_output.nested_detections.clone()
            );
        }
        Err(err) => println!("{:?}", err)
    }

    value(ParserOutput { result: {condition.clone()}}, tag_no_case(result_condition.clone().as_str()))(input.trim())
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


#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::structs::detection::Detection;

    #[test]
    fn or_parens_parser_condition() {
        let result = or_parser("or (filter and not selection)");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::OR,
                        parser_result: "or (filter and not selection)".to_string(),
                    },
                    is_negated: Some(false),
                    operator: Some(OPERATOR::OR),
                    search_identifier: None,
                    nested_detections: Some(Detection {
                        operator: Some(OPERATOR::AND),
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
                                    parser_type: PARSER_TYPES::AND,
                                    parser_result: "and not selection".to_string()
                                },
                                is_negated: Some(true),
                                operator: Some(OPERATOR::AND),
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
    fn or_not_parser_condition() {
        let result = or_parser("or not filter");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::OR,
                        parser_result: "or not filter".to_string(),
                    },
                    is_negated: Some(true),
                    operator: Some(OPERATOR::OR),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn or_parser_condition() {
        let result = or_parser("or filter");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::OR,
                        parser_result: "or filter".to_string(),
                    },
                    is_negated: Some(false),
                    operator: Some(OPERATOR::OR),
                    search_identifier: Some("filter".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn or_parens_input() {
        let parser_result = or(" or (events and selection) ");
        assert_eq!(parser_result, Ok((" (events and selection)", "or")));
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