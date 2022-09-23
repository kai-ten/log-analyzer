use nom::bytes::complete::tag;
use nom::IResult;
use nom::sequence::delimited;

use crate::operator_parsers::parser;
use crate::parser_output::ParserOutput;
use crate::structs::condition::{Condition, PARSER_TYPES};
use crate::structs::detection::Detection;
use crate::take_until_unbalanced::take_until_unbalanced;


pub fn parens_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {

    let mut detection = Detection::new(); // groups the conditions in the parentheses
    let mut condition_result = Condition::new(); // builds the conditions in the parentheses

    let (remaining, result) = parens(input)?;

    let mut remaining_condition = remaining;
    let mut result_condition = result;


    while !result_condition.is_empty() {

        match parser(result_condition) {
            Ok((remaining, condition)) => {
                result_condition = remaining;

                match condition.parser_type.as_ref().unwrap() {
                    PARSER_TYPES::PARENS => {
                        condition_result.nested_detections = condition.nested_detections.clone();
                        condition_result.parser_result = condition.parser_result.clone();
                        condition_result.is_negated = Some(condition.is_negated.unwrap_or(false));
                        detection.conditions = Some(vec![condition.input]);
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
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition_result.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::AND => {
                        detection.operator = condition.operator.clone();
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition_result.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::OR => {
                        detection.operator = condition.operator.clone();
                        condition_result = condition.input.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition_result.clone());
                        detection.conditions = Some(conditions);
                    },
                    PARSER_TYPES::PIPE => {
                        println!("PIPE SHOULD RETURN ERROR")
                    },
                    PARSER_TYPES::SEARCH_IDENTIFIER => {
                        detection.conditions = Some(vec![condition.input]);
                    },
                    _ => {
                        print!("I DONT KNOW YET, ERROR MAYBE???");
                    }
                }

            },
            Err(..) => {}
        }

    }

    let mut condition = Condition::new();
    condition.parser_type = Some(PARSER_TYPES::PARENS);
    condition.parser_result = condition_result.parser_result;
    condition.nested_detections = Some(detection);

    Ok((remaining_condition, ParserOutput {input: condition}))
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
    use crate::structs::condition::{Condition, OPERATOR, PARSER_TYPES};
    use crate::structs::condition::OPERATOR::AND;
    use crate::structs::detection::Detection;

    #[test]
    fn nested_parens_parser_condition() {
        let result = parens_parser("(Selection or (not Filter and Selection1)) and Keywords");
        assert_eq!(result, Ok((" and Keywords", ParserOutput { input:
        Condition {
            parser_type: Some(PARSER_TYPES::PARENS),
            parser_result: Some(vec!["and".to_string(), "Selection1".to_string()]),
            is_negated: None,
            operator: None,
            search_identifier: None,
            nested_detections: Some(Detection {
                operator: None,
                conditions: Some(vec![
                    Condition {
                        parser_type: Some(PARSER_TYPES::PARENS),
                        parser_result: Some(vec!["and".to_string(), "Selection1".to_string()]),
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(AND),
                            conditions: Some(vec![
                                Condition {
                                    parser_type: Some(PARSER_TYPES::NOT),
                                    parser_result: Some(vec!["not".to_string(), "Filter".to_string()]),
                                    is_negated: Some(true),
                                    operator: None,
                                    search_identifier: Some("Filter".to_string()),
                                    nested_detections: None
                                },
                                Condition {
                                    parser_type: Some(PARSER_TYPES::AND),
                                    parser_result: Some(vec!["and".to_string(), "Selection1".to_string()]),
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
        }})))
    }


    /// Only parentheses can be passed into this parser. For that reason, all inputs will start with
    /// (remaining: &str, result: &str), and the value inside of the parentheses will always be result.
    #[test]
    fn parens_parser_condition() {
        let result = parens_parser("(Selection or not Filter) and Keywords");
        assert_eq!(result, Ok((" and Keywords",
            ParserOutput {
                input: Condition {
                    parser_type: Some(PARSER_TYPES::PARENS),
                    parser_result: Some(vec!["or".to_string(), "not".to_string(), "Filter".to_string()]),
                    is_negated: None,
                    operator: None,
                    search_identifier: None,
                    nested_detections: Some(Detection {
                        operator: Some(OPERATOR::OR),
                        conditions: Some(vec![
                            Condition {
                                parser_type: Some(PARSER_TYPES::SEARCH_IDENTIFIER),
                                parser_result: Some(vec!["Selection".to_string()]),
                                is_negated: None, operator: None,
                                search_identifier: Some("Selection".to_string()),
                                nested_detections: None
                            },
                            Condition {
                                parser_type: Some(PARSER_TYPES::OR),
                                parser_result: Some(vec!["or".to_string(), "not".to_string(), "Filter".to_string()]),
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
