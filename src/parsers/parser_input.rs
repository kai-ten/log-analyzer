// use nom::{AsBytes, Compare, CompareResult, ExtendInto, FindToken, InputIter, InputLength, InputTake, InputTakeAtPosition, IResult, Needed, Offset, ParseTo, Slice};
// use nom::error::{ErrorKind, ParseError};
// use crate::detection::Condition;
// use std::cmp;
//
// #[derive(Debug, Clone, Copy)]
// struct ParserInput {
//     input: String,
//     condition: Condition,
// }
//
// // struct ParserOutput {
// //
// // }
//
// impl ParserInput {
//     pub fn new(input: String, condition: Condition) -> ParserInput {
//         ParserInput {
//             input,
//             condition,
//         }
//     }
// }
//
// impl AsBytes for ParserInput {
//     fn as_bytes(&self) -> &[u8] {
//         &self.input.as_bytes()
//     }
// }
// impl<T> Compare<T> for ParserInput {
//     fn compare(&self, t: T) -> CompareResult {
//         self.input.compare(t)
//     }
//
//     fn compare_no_case(&self, t: T) -> CompareResult {
//         self.compare_no_case(t)
//     }
// }
//
// // #[cfg(feature = "alloc")] ----- TODO - get answer to why is this used in nom_locate
// /// Builds and Returns type ParserInput
// impl ExtendInto for ParserInput {
//     type Item = ParserInput;
//     type Extender = ParserInput;
//
//
//     fn new_builder(&self) -> Self::Extender {
//         self.new_builder()
//     }
//     fn extend_into(&self, acc: &mut Self::Extender) {
//         self.extend_into(acc)
//     }
//
// }
//
// impl<T> FindSubString<T> for ParserInput {
//     // fn find_substring(&self, substr: T) -> Option<usize> {
//     //     todo!()
//     //
//     // }
//     // #[inline]
//     fn find_substring(&self, substr: U) -> Option<usize> {
//         self.find_substring(substr);
//     }
// }
//
// impl<T> FindToken<T> for ParserInput {
//     fn find_token(&self, token: T) -> bool {
//         self.find_token(token)
//     }
//
// }
//
// impl InputIter for ParserInput {
//     type Item = ();
//     type Iter = ();
//     type IterElem = ();
//
//     fn iter_indices(&self) -> Self::Iter {
//         todo!()
//     }
//
//     fn iter_elements(&self) -> Self::IterElem {
//         todo!()
//     }
//
//     fn position<P>(&self, predicate: P) -> Option<usize> where P: Fn(Self::Item) -> bool {
//         todo!()
//     }
//
//     fn slice_index(&self, count: usize) -> Result<usize, Needed> {
//         todo!()
//     }
// }
//
// impl InputLength for ParserInput {
//     fn input_len(&self) -> usize {
//         todo!()
//     }
// }
//
// impl InputTake for ParserInput {
//     fn take(&self, count: usize) -> Self {
//         todo!()
//     }
//     fn take_split(&self, count: usize) -> (Self, Self) {
//         todo!()
//     }
// }
//
// impl InputTakeAtPosition for ParserInput {
//     type Item = ();
//     fn split_at_position<P, E: ParseError<Self>>(&self, predicate: P) -> IResult<Self, Self, E> where P: Fn(Self::Item) -> bool {
//         todo!()
//     }
//     fn split_at_position1<P, E: ParseError<Self>>(&self, predicate: P, e: ErrorKind) -> IResult<Self, Self, E> where P: Fn(Self::Item) -> bool {
//         todo!()
//     }
//     fn split_at_position_complete<P, E: ParseError<Self>>(&self, predicate: P) -> IResult<Self, Self, E> where P: Fn(Self::Item) -> bool {
//         todo!()
//     }
//     fn split_at_position1_complete<P, E: ParseError<Self>>(&self, predicate: P, e: ErrorKind) -> IResult<Self, Self, E> where P: Fn(Self::Item) -> bool {
//         todo!()
//     }
//
// }
//
// impl Offset for ParserInput {
//     fn offset(&self, second: &Self) -> usize {
//         let fst = self.input.offset();
//         let snd = second.offset();
//
//         fst - sndl
//     }
// }
//
// impl ParseTo<R> for ParserInput {
//     fn parse_to(&self) -> Option<R> {
//         self.input.parse_to()
//     }
// }
//
// impl Slice<R> for ParserInput {
//     fn slice(&self, range: R) -> Self {
//         self.input.slice(range)
//     }
// }
//
//
