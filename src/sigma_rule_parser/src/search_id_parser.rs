use nom::branch::alt;
use nom::bytes::complete::{tag_no_case, take_until, take_while};
use nom::combinator::{rest, value};
use nom::IResult;
use crate::and_parser::and_parser;
use crate::or_parser::or_parser;

use crate::parser_output::ParserOutput;
use crate::structs::condition::{Condition, Metadata, OPERATOR, PARSER_TYPES};


pub fn search_identifiers_parser(
    input: &str
) -> IResult<&str, ParserOutput<Condition>> {
    let (_, result) = search_identifiers(input)?;
    let metadata = Metadata::new(PARSER_TYPES::SEARCH_IDENTIFIER, String::from(result));

    let condition = Condition::new(
        metadata,
        None,
        None,
        Some(String::from(result)),
        None,
    );

    // TODO: why this different than below method, must validate error handling somehow
    value(ParserOutput { result: { condition.clone() } }, take_while(|ch| ch != ' '))(input.trim())

    // let mut condition = Condition::init();
    //
    // let (remaining, result) = search_identifiers(input)?;
    // let mut result_condition: String = String::from(result);
    //
    // let search_id_parser_result = downstream_search_id_parser(remaining.trim());
    // match search_id_parser_result {
    //     Ok((_, parser_output)) => {
    //         let downstream_parser_result = parser_output.metadata.parser_result.clone();
    //         result_condition = format!("{}{}{}", result_condition, " ", remaining.trim());
    //
    //         println!("{:?}", result_condition);
    //
    //         let metadata = Metadata::new(
    //             PARSER_TYPES::AND,
    //             result_condition.clone()
    //         );
    //
    //         condition = Condition::new(
    //             metadata,
    //             Some(parser_output.is_negated.unwrap_or(false)),
    //             Some(OPERATOR::AND),
    //             parser_output.search_identifier.clone(),
    //             parser_output.nested_detections.clone()
    //         );
    //     }
    //     Err(_) => {}
    // }
    //
    // value(ParserOutput { result: {condition.clone()}}, tag_no_case(result_condition.clone().as_str()))(input.trim())
}

// need to implement the possible parsers that may follow a search identifier - and / or
fn downstream_search_id_parser(input: &str) -> IResult<&str, ParserOutput<Condition>> {
    let result = alt((
        and_parser,
        or_parser,
    ))(input);

    result
}

/// Returns search identifiers within a condition (take_until(" ")), and at the end of a condition (rest of string)
/// Returns the remaining string to parse, the result that was parsed, and the condition being updated.
/// A successful response indicates that the condition is completed and ready to be stored in a Detection struct
/// A failure indicates invalid input, or potentially a missed parsing use-case.
fn search_identifiers(
    input: &str
) -> IResult<&str, &str> {
    let sid = alt((take_until(" "), rest))(input.trim());

    let sid_result = match sid {
        Ok(parsed_sid) => parsed_sid,
        Err(e) => return Err(e),
    };

    Ok(sid_result)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_search_identifiers() {
        let result = search_identifiers_parser("Selection and not Filter");
        println!("{:?}", result);
    }

    #[test]
    fn search_identifier_condition() {
        let result = search_identifiers_parser("Selection");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                        parser_result: String::from("Selection"),
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("Selection".to_string()),
                    nested_detections: None
                }
            }
        )));

        let result = search_identifiers_parser("");
        assert_eq!(result, Ok((
            "",
            ParserOutput {
                result: Condition {
                    metadata: Metadata {
                        parser_type: PARSER_TYPES::SEARCH_IDENTIFIER,
                        parser_result: String::from(""),
                    },
                    is_negated: None,
                    operator: None,
                    search_identifier: Some("".to_string()),
                    nested_detections: None
                }
            }
        )));
    }

    #[test]
    fn search_identifier_input() {
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
