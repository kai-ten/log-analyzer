use nom::{AsBytes, Compare, CompareResult, ExtendInto, FindSubstring, FindToken, InputIter, InputLength, InputTake, InputTakeAtPosition, IResult, Offset, ParseTo, Slice};
use nom::error::{ErrorKind, ParseError};
use nom::Err::{Error, Incomplete};

use std::ops::{RangeFrom, RangeTo};
use std::str::FromStr;


#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ParserOutput<T> {
    pub result: T
}

impl<T> ParserOutput<T> {
    pub fn new(result: T) -> ParserOutput<T> {
        ParserOutput {
            result
        }
    }

    pub fn input(&self) -> &T {
        &self.result
    }
}

impl<T> core::ops::Deref for ParserOutput<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

impl<T: AsBytes> ParserOutput<T> {
    fn as_bytes(&self) -> &[u8] {
        &self.result.as_bytes()
    }
}

impl<T: Compare<B>, B: Into<ParserOutput<B>>> Compare<B> for ParserOutput<T> {
    #[inline(always)]
    fn compare(&self, t: B) -> CompareResult {
        self.result.compare(t.into().result)
    }

    #[inline(always)]
    fn compare_no_case(&self, t: B) -> CompareResult {
        self.result.compare_no_case(t.into().result)
    }
}

// #[cfg(feature = "alloc")] ----- TODO - get answer to why is this used in nom_locate
/// Builds and Returns type ParserInput
impl<'a, T> ExtendInto for ParserOutput<T>
where
    T: ExtendInto,
{
    type Item = T::Item;
    type Extender = T::Extender;

    fn new_builder(&self) -> Self::Extender {
        self.result.new_builder()
    }
    fn extend_into(&self, acc: &mut Self::Extender) {
        self.result.extend_into(acc)
    }
}

impl<T, U> FindSubstring<U> for ParserOutput<T>
where
    T: FindSubstring<U>,
{
    #[inline]
    fn find_substring(&self, substr: U) -> Option<usize> {
        self.result.find_substring(substr)
    }
}

impl<T: FindToken<Token>, Token> FindToken<Token> for ParserOutput<T> {
    fn find_token(&self, token: Token) -> bool {
        self.result.find_token(token)
    }
}

impl<'a, T> InputIter for ParserOutput<T>
where
    T: InputIter,
{
    type Item = T::Item;
    type Iter = T::Iter;
    type IterElem = T::IterElem;

    #[inline]
    fn iter_indices(&self) -> Self::Iter {
        self.result.iter_indices()
    }
    #[inline]
    fn iter_elements(&self) -> Self::IterElem {
        self.result.iter_elements()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
        where
            P: Fn(Self::Item) -> bool,
    {
        self.result.position(predicate)
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        self.result.slice_index(count)
    }
}

impl<T: InputLength> InputLength for ParserOutput<T> {
    fn input_len(&self) -> usize {
        self.result.input_len()
    }
}

impl<T> InputTake for ParserOutput<T>
    where
        Self: Slice<RangeFrom<usize>> + Slice<RangeTo<usize>>,
{
    fn take(&self, count: usize) -> Self {
        self.slice(..count)
    }
    fn take_split(&self, count: usize) -> (Self, Self) {
        (self.slice(count..), self.slice(..count))
    }
}

impl<T> InputTakeAtPosition for ParserOutput<T>
where
    T: InputTakeAtPosition + InputLength + InputIter,
    Self: Slice<RangeFrom<usize>> + Slice<RangeTo<usize>> + Clone,
{
    type Item = <T as InputIter>::Item;

    fn split_at_position<P, E: ParseError<Self>>(&self, predicate: P) -> IResult<Self, Self, E>
        where
            P: Fn(Self::Item) -> bool,
    {
        match self.result.position(predicate) {
            Some(n) => Ok(self.take_split(n)),
            None => Err(Incomplete(nom::Needed::new(1))),
        }
    }

    fn split_at_position1<P, E: ParseError<Self>>(
        &self,
        predicate: P,
        e: ErrorKind,
    ) -> IResult<Self, Self, E>
        where
            P: Fn(Self::Item) -> bool,
    {
        match self.result.position(predicate) {
            Some(0) => Err(Error(E::from_error_kind(self.clone(), e))),
            Some(n) => Ok(self.take_split(n)),
            None => Err(Incomplete(nom::Needed::new(1))),
        }
    }

    fn split_at_position_complete<P, E: ParseError<Self>>(
        &self,
        predicate: P,
    ) -> IResult<Self, Self, E>
        where
            P: Fn(Self::Item) -> bool,
    {
        match self.split_at_position(predicate) {
            Err(Incomplete(_)) => Ok(self.take_split(self.input_len())),
            res => res,
        }
    }

    fn split_at_position1_complete<P, E: ParseError<Self>>(
        &self,
        predicate: P,
        e: ErrorKind,
    ) -> IResult<Self, Self, E>
        where
            P: Fn(Self::Item) -> bool,
    {
        match self.result.position(predicate) {
            Some(0) => Err(Error(E::from_error_kind(self.clone(), e))),
            Some(n) => Ok(self.take_split(n)),
            None => {
                if self.result.input_len() == 0 {
                    Err(Error(E::from_error_kind(self.clone(), e)))
                } else {
                    Ok(self.take_split(self.input_len()))
                }
            }
        }
    }
}

impl<T> Offset for ParserOutput<T> {
    fn offset(&self, second: &Self) -> usize {
        let fst = self.offset(self);
        let snd = second.offset(second);

        snd - fst
    }
}

impl<R: FromStr,T: ParseTo<R>> ParseTo<R> for ParserOutput<T> {
    #[inline]
    fn parse_to(&self) -> Option<R> {
        self.result.parse_to()
    }
}

impl<'a, T, R> Slice<R> for ParserOutput<T>
    where
        T: Slice<R> + Offset + AsBytes + Slice<RangeTo<usize>>,
{
    fn slice(&self, range: R) -> Self {
        let next_fragment = self.result.slice(range);
        let consumed_len = self.result.offset(&next_fragment);
        if consumed_len == 0 {
            return ParserOutput {
                result: next_fragment
            };
        }

        // let consumed = self.input.slice(..consumed_len);

        // let next_offset = self.offset(self) + consumed_len;

        // let consumed_as_bytes = consumed.as_bytes();
        // let iter = Memchr::new(b'\n', consumed_as_bytes);
        // let number_of_lines = iter.count() as u32;
        // let next_line = self.line + number_of_lines;

        ParserOutput {
            result: next_fragment
        }
    }
}


