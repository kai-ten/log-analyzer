use nom::bytes::complete::tag;
use nom::IResult;
use nom::sequence::delimited;

use crate::operator_parsers::parser;
use crate::parser_output::ParserOutput;
use crate::structs::condition::{Condition, Metadata, PARSER_TYPES};
use crate::structs::detection::Detection;
use crate::take_until_unbalanced::take_until_unbalanced;


pub fn parens_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut condition = Condition::init(); // builds the conditions in the parentheses

    let (remaining, result) = parens(input)?;

    let mut remaining_condition = remaining;
    let mut resulting_condition = result;


    // while !remaining_condition.is_empty() {
    //     println!("yo are u the real slim shady")
    // }

    while !resulting_condition.is_empty() {

        match parser(resulting_condition) {
            Ok((remaining, parser_output)) => {
                resulting_condition = remaining;

                println!("{:?}", resulting_condition);

                match parser_output.metadata.parser_type.clone() {
                    PARSER_TYPES::PARENS => {
                        condition.metadata = parser_output.metadata.clone();
                        condition.nested_detections = parser_output.nested_detections.clone();
                        detection.conditions = Some(vec![parser_output.result]);
                    },
                    PARSER_TYPES::ONE_OF_THEM => {
                        println!("ONE_OF_THEM");
                    },
                    PARSER_TYPES::ALL_OF_THEM => {
                        println!("ALL_OF_THEM");
                    },
                    PARSER_TYPES::ONE_OF => {
                        println!("ONE_OF");
                    },
                    PARSER_TYPES::ALL_OF => {
                        println!("ALL_OF");
                    },
                    PARSER_TYPES::NOT => {
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::AND => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::OR => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::PIPE => {
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE");
                    },
                    PARSER_TYPES::SEARCH_IDENTIFIER => {
                        detection.conditions = Some(vec![parser_output.result]);
                    },
                    _ => {
                        print!("I DONT KNOW YET, ERROR MAYBE???");
                    }
                }

            }
            Err(..) => {}
        }

    }

    let mut condition_clone = Condition::init();

    let metadata = Metadata {
        parser_type: PARSER_TYPES::PARENS,
        parser_result: condition.metadata.parser_result.clone(),
    };

    condition_clone.metadata = metadata;
    condition_clone.nested_detections = Some(detection);

    Ok((remaining_condition, ParserOutput { result: condition_clone}))
}

fn parens(input: &str) -> IResult<&str, &str> {
    delimited(tag("("), take_until_unbalanced('(', ')'), tag(")"))(input.trim())
}


#[cfg(test)]
mod tests {

    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};
    use crate::parens_parser::{parens, parens_parser};
    use crate::parser_output::ParserOutput;
    use crate::structs::condition::{Condition, Metadata, OPERATOR, PARSER_TYPES};
    use crate::structs::condition::OPERATOR::AND;
    use crate::structs::detection::Detection;


    // this test is looking not better
    #[test]
    fn nested_parens_parser_condition() {
        let result = parens_parser("(Selection or (not Filter and Selection1)) and Keywords");
        assert_eq!(result, Ok((" and Keywords", ParserOutput { result:
        Condition {
            metadata: Metadata {
                parser_type: PARSER_TYPES::PARENS,
                parser_result: "".to_string(),
            },
            is_negated: None,
            operator: None,
            search_identifier: None,
            nested_detections: Some(Detection {
                operator: None,
                conditions: Some(vec![
                    Condition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::PARENS,
                            parser_result: "and Selection1".to_string(),
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(AND),
                            conditions: Some(vec![
                                Condition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::NOT,
                                        parser_result: "not Filter".to_string(),
                                    },
                                    is_negated: Some(true),
                                    operator: None,
                                    search_identifier: Some("Filter".to_string()),
                                    nested_detections: None
                                },
                                Condition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::AND,
                                        parser_result: "and Selection1".to_string(),
                                    },
                                    is_negated: Some(false),
                                    operator: Some(AND),
                                    search_identifier: Some("Selection1".to_string()),
                                    nested_detections: None
                                }
                            ])
                        })
                    }
                ])
            })
        }})));


        // (Selection or (not Filter and Selection1)) and Keywords
        let oney = ParserOutput {
            result: Condition {
                metadata: Metadata {
                    parser_type: PARSER_TYPES::PARENS,
                    parser_result: "or (not Filter and Selection1)".to_string()
                },
                is_negated: None,
                operator: None,
                search_identifier: None,
                nested_detections: Some(Detection {
                    operator: Some(OPERATOR::OR),
                    conditions: Some(vec![
                        Condition {
                            metadata: Metadata {
                                parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                                parser_result: "Selection".to_string()
                            },
                            is_negated: None,
                            operator: None,
                            search_identifier: Some("Selection".to_string()),
                            nested_detections: None
                        },
                        Condition {
                            metadata: Metadata {
                                parser_type: PARSER_TYPES::OR,
                                parser_result: "or (not Filter and Selection1)".to_string()
                            },
                            is_negated: Some(false),
                            operator: Some(OPERATOR::OR),
                            search_identifier: None,
                            nested_detections: Some(Detection {
                                operator: Some(AND),
                                conditions: Some(vec![
                                    Condition {
                                        metadata: Metadata {
                                            parser_type: PARSER_TYPES::NOT,
                                            parser_result: "not Filter".to_string()
                                        },
                                        is_negated: Some(true),
                                        operator: None,
                                        search_identifier: Some("Filter".to_string()),
                                        nested_detections: None
                                    },
                                    Condition { metadata: Metadata {
                                        parser_type: PARSER_TYPES::AND,
                                        parser_result: "and Selection1".to_string()
                                    },
                                        is_negated: Some(false),
                                        operator: Some(AND),
                                        search_identifier: Some("Selection1".to_string()),
                                        nested_detections: None
                                    }
                                ])
                            })
                        }
                    ])
                })
            }
        };

    }


    /// Only parentheses can be passed into this parser. For that reason, all inputs will start with
    /// (remaining: &str, result: &str), and the value inside of the parentheses will always be result.
    #[test]
    fn parens_parser_condition() {
        let result = parens_parser("(Selection or not Filter) and Keywords");
        assert_eq!(result, Ok((" and Keywords",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::PARENS,
                        parser_result: "or not Filter".to_string(),
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: None,
                    nested_detections: Some(Detection {
                        operator: Some(OPERATOR::OR),
                        conditions: Some(vec![
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                                    parser_result: "Selection".to_string(),
                                },
                                is_negated: None, operator: None,
                                search_identifier: Some("Selection".to_string()),
                                nested_detections: None
                            },
                            Condition {
                                metadata: Metadata {
                                    parser_type: PARSER_TYPES::OR,
                                    parser_result: "or not Filter".to_string(),
                                },
                                is_negated: Some(true),
                                operator: Some(OPERATOR::OR),
                                search_identifier: Some("Filter".to_string()),
                                nested_detections: None
                            }
                        ])
                    })
                }
            }
        )))
        // let nice = parens_parser("Keywords or (Selection and Filter)");
        // assert_eq!(nice, Error { input: "Keywords or (Selection and Filter)", code: Tag });
    }

    #[test]
    fn parens_input() {
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
}



// "Not Selection and Filter"
// not parser - not
//     search id parser - selection, saves condition
//
// and parser - looks at detection.conditions
//     search id parser - Filter, saves condition
//
//
//
//
// "Filter and Not Selection"
//
//
// CANNOT HAVE "and/or Filter"
