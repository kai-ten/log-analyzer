use nom::bytes::complete::tag_no_case;
use nom::IResult;


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

pub fn pipe(input: &str) -> IResult<&str, &str> {
    tag_no_case("|")(input.trim())
}



fn parser_str_builder(input: Option<Vec<String>>) -> String {
    input.as_ref().unwrap().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind::Tag;
    use nom::error::{Error, ParseError};


    // Do this stuff eventually
    ///////////////////////////////
    ///////////////////////////////
    ///////////////////////////////

    // #[test]
    // fn one_of_them_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn all_of_them_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn one_of_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }
    //
    // #[test]
    // fn all_of_input() {
    //     let parser_result = not(" not events ");
    //     assert_eq!(parser_result, Ok((" events", "not")));
    //
    //     let parser_result = not(" and events ");
    //     assert_eq!(
    //         parser_result,
    //         Err(nom::Err::Error(Error::from_error_kind("and events", Tag)))
    //     );
    // }

    ///////////////////////////////
    ///////////////////////////////
    ///////////////////////////////

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
}
