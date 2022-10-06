use nom::bytes::complete::tag;
use nom::sequence::delimited;
use nom::IResult;

use crate::structs::detection_condition::{DetectionCondition, Metadata, PARSER_TYPES};
use crate::structs::detection::Detection;
use crate::sub_parsers::sub_parsers::parser;
use crate::sub_parsers::parser_output::ParserOutput;
use crate::sub_parsers::take_until_unbalanced::take_until_unbalanced;

pub fn parens_parser(input: &str) -> IResult<&str, ParserOutput<DetectionCondition>> {
    let mut detection = Detection::init(); // groups the conditions in the parentheses
    let mut condition = DetectionCondition::init(); // builds the conditions in the parentheses

    let (remaining, result) = parens(input)?;
    let mut remaining_condition = remaining;
    let mut resulting_condition = result;

    while !resulting_condition.is_empty() {
        match parser(resulting_condition) {
            Ok((remaining, parser_output)) => {
                resulting_condition = remaining;

                match parser_output.metadata.parser_type.clone() {
                    PARSER_TYPES::Parens => {
                        condition = parser_output.result.clone();
                        detection.conditions = Some(vec![parser_output.result.clone()]);
                    }
                    PARSER_TYPES::OneOfThem => {
                        println!("ONE_OF_THEM");
                    }
                    PARSER_TYPES::AllOfThem => {
                        println!("ALL_OF_THEM");
                    }
                    PARSER_TYPES::OneOf => {
                        println!("ONE_OF");
                    }
                    PARSER_TYPES::AllOf => {
                        println!("ALL_OF");
                    }
                    PARSER_TYPES::Not => {
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap_or(vec![]);
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::And => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::Or => {
                        detection.operator = parser_output.operator.clone();
                        condition = parser_output.result.clone();

                        let mut conditions = detection.conditions.unwrap();
                        conditions.push(condition.clone());
                        detection.conditions = Some(conditions);
                    }
                    PARSER_TYPES::Pipe => {
                        println!("PIPE SHOULD RETURN ERROR FOR NOW AND CONTINUE TO NEXT RULE");
                    }
                    PARSER_TYPES::SearchIdentifier => {
                        detection.conditions = Some(vec![parser_output.result]);
                    }
                    _ => {
                        print!("I DONT KNOW YET, ERROR MAYBE???");
                    }
                }
            }
            Err(..) => {}
        }
    }

    let mut parser_result = format!("{}{}{}", "(", result.to_string(), ")");
    let metadata = Metadata {
        parser_type: PARSER_TYPES::Parens,
        parser_result,
    };

    let mut result_condition = DetectionCondition::init();
    result_condition.metadata = metadata;
    result_condition.nested_detections = Some(detection);

    Ok((
        remaining_condition,
        ParserOutput {
            result: result_condition,
        },
    ))
}

fn parens(input: &str) -> IResult<&str, &str> {
    delimited(tag("("), take_until_unbalanced('(', ')'), tag(")"))(input.trim())
}

#[cfg(test)]
mod tests {

    use crate::structs::detection_condition::OPERATOR::And;
    use crate::structs::detection_condition::{DetectionCondition, Metadata, OPERATOR, PARSER_TYPES};
    use crate::structs::detection::Detection;
    use crate::sub_parsers::parens_parser::{parens, parens_parser};
    use crate::sub_parsers::parser_output::ParserOutput;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};

    // this test is looking not better
    #[test]
    fn nested_parens_parser_condition() {
        let result = parens_parser("( Selection or (not Filter and Selection1) ) and Keywords");
        assert_eq!(
            result,
            Ok((
                " and Keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::Parens,
                            parser_result: "( Selection or (not Filter and Selection1) )"
                                .to_string()
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(OPERATOR::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::SearchIdentifier,
                                        parser_result: "Selection".to_string()
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("Selection".to_string()),
                                    nested_detections: None
                                },
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::Or,
                                        parser_result: "or (not Filter and Selection1)".to_string()
                                    },
                                    is_negated: None,
                                    operator: Some(OPERATOR::Or),
                                    search_identifier: None,
                                    nested_detections: Some(Detection {
                                        operator: Some(And),
                                        conditions: Some(vec![
                                            DetectionCondition {
                                                metadata: Metadata {
                                                    parser_type: PARSER_TYPES::Not,
                                                    parser_result: "not Filter".to_string()
                                                },
                                                is_negated: Some(true),
                                                operator: None,
                                                search_identifier: Some("Filter".to_string()),
                                                nested_detections: None
                                            },
                                            DetectionCondition {
                                                metadata: Metadata {
                                                    parser_type: PARSER_TYPES::And,
                                                    parser_result: "and Selection1".to_string()
                                                },
                                                is_negated: None,
                                                operator: Some(And),
                                                search_identifier: Some("Selection1".to_string()),
                                                nested_detections: None
                                            }
                                        ])
                                    })
                                }
                            ])
                        })
                    }
                }
            ))
        );
    }

    /// Only parentheses can be passed into this parser. For that reason, all inputs will start with
    /// (remaining: &str, result: &str), and the value inside of the parentheses will always be result.
    #[test]
    fn parens_parser_condition() {
        let result = parens_parser("(Selection or not Filter) and Keywords");
        assert_eq!(
            result,
            Ok((
                " and Keywords",
                ParserOutput {
                    result: DetectionCondition {
                        metadata: Metadata {
                            parser_type: PARSER_TYPES::Parens,
                            parser_result: "(Selection or not Filter)".to_string(),
                        },
                        is_negated: None,
                        operator: None,
                        search_identifier: None,
                        nested_detections: Some(Detection {
                            operator: Some(OPERATOR::Or),
                            conditions: Some(vec![
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::SearchIdentifier,
                                        parser_result: "Selection".to_string(),
                                    },
                                    is_negated: None,
                                    operator: None,
                                    search_identifier: Some("Selection".to_string()),
                                    nested_detections: None
                                },
                                DetectionCondition {
                                    metadata: Metadata {
                                        parser_type: PARSER_TYPES::Or,
                                        parser_result: "or not Filter".to_string(),
                                    },
                                    is_negated: Some(true),
                                    operator: Some(OPERATOR::Or),
                                    search_identifier: Some("Filter".to_string()),
                                    nested_detections: None
                                }
                            ])
                        })
                    }
                }
            ))
        )
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
