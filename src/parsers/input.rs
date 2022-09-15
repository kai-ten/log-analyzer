use nom::{AsBytes, Compare, CompareResult, ExtendInto, FindSubstring, FindToken, InputIter, InputLength, InputTake, InputTakeAtPosition, IResult, Needed, Offset, ParseTo, Slice};
use nom::error::{ErrorKind, ParseError};
use std::cmp;
use std::ops::{RangeFrom, RangeTo};
use std::str::FromStr;
use nom::Err::{Error, Incomplete};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConditionInput<T> {
    pub(crate) input: T
}

impl<T> ConditionInput<T> {
    pub fn new(input: T) -> ConditionInput<T> {
        ConditionInput {
            input
        }
    }

    pub fn input(&self) -> &T {
        &self.input
    }
}

impl<T> core::ops::Deref for ConditionInput<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl<T: AsBytes> ConditionInput<T> {
    fn as_bytes(&self) -> &[u8] {
        &self.input.as_bytes()
    }
}

impl<T: Compare<B>, B: Into<ConditionInput<B>>> Compare<B> for ConditionInput<T> {
    #[inline(always)]
    fn compare(&self, t: B) -> CompareResult {
        self.input.compare(t.into().input)
    }

    #[inline(always)]
    fn compare_no_case(&self, t: B) -> CompareResult {
        self.input.compare_no_case(t.into().input)
    }
}

// #[cfg(feature = "alloc")] ----- TODO - get answer to why is this used in nom_locate
/// Builds and Returns type ParserInput
impl<'a, T> ExtendInto for ConditionInput<T>
where
    T: ExtendInto,
{
    type Item = T::Item;
    type Extender = T::Extender;

    fn new_builder(&self) -> Self::Extender {
        self.input.new_builder()
    }
    fn extend_into(&self, acc: &mut Self::Extender) {
        self.input.extend_into(acc)
    }
}

impl<T, U> FindSubstring<U> for ConditionInput<T>
where
    T: FindSubstring<U>,
{
    #[inline]
    fn find_substring(&self, substr: U) -> Option<usize> {
        self.input.find_substring(substr)
    }
}

impl<T: FindToken<Token>, Token> FindToken<Token> for ConditionInput<T> {
    fn find_token(&self, token: Token) -> bool {
        self.input.find_token(token)
    }
}

impl<'a, T> InputIter for ConditionInput<T>
where
    T: InputIter,
{
    type Item = T::Item;
    type Iter = T::Iter;
    type IterElem = T::IterElem;

    #[inline]
    fn iter_indices(&self) -> Self::Iter {
        self.input.iter_indices()
    }
    #[inline]
    fn iter_elements(&self) -> Self::IterElem {
        self.input.iter_elements()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
        where
            P: Fn(Self::Item) -> bool,
    {
        self.input.position(predicate)
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        self.input.slice_index(count)
    }
}

impl<T: InputLength> InputLength for ConditionInput<T> {
    fn input_len(&self) -> usize {
        self.input.input_len()
    }
}

impl<T> InputTake for ConditionInput<T>
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

impl<T> InputTakeAtPosition for ConditionInput<T>
where
    T: InputTakeAtPosition + InputLength + InputIter,
    Self: Slice<RangeFrom<usize>> + Slice<RangeTo<usize>> + Clone,
{
    type Item = <T as InputIter>::Item;

    fn split_at_position<P, E: ParseError<Self>>(&self, predicate: P) -> IResult<Self, Self, E>
        where
            P: Fn(Self::Item) -> bool,
    {
        match self.input.position(predicate) {
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
        match self.input.position(predicate) {
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
        match self.input.position(predicate) {
            Some(0) => Err(Error(E::from_error_kind(self.clone(), e))),
            Some(n) => Ok(self.take_split(n)),
            None => {
                if self.input.input_len() == 0 {
                    Err(Error(E::from_error_kind(self.clone(), e)))
                } else {
                    Ok(self.take_split(self.input_len()))
                }
            }
        }
    }
}

impl<T> Offset for ConditionInput<T> {
    fn offset(&self, second: &Self) -> usize {
        let fst = self.offset(self);
        let snd = second.offset(second);

        snd - fst
    }
}

impl<R: FromStr,T: ParseTo<R>> ParseTo<R> for ConditionInput<T> {
    #[inline]
    fn parse_to(&self) -> Option<R> {
        self.input.parse_to()
    }
}

impl<'a, T, R> Slice<R> for ConditionInput<T>
    where
        T: Slice<R> + Offset + AsBytes + Slice<RangeTo<usize>>,
{
    fn slice(&self, range: R) -> Self {
        let next_fragment = self.input.slice(range);
        let consumed_len = self.input.offset(&next_fragment);
        if consumed_len == 0 {
            return ConditionInput {
                input: next_fragment
            };
        }

        let consumed = self.input.slice(..consumed_len);

        let next_offset = self.offset(self) + consumed_len;

        // let consumed_as_bytes = consumed.as_bytes();
        // let iter = Memchr::new(b'\n', consumed_as_bytes);
        // let number_of_lines = iter.count() as u32;
        // let next_line = self.line + number_of_lines;

        ConditionInput {
            input: next_fragment
        }
    }
}


