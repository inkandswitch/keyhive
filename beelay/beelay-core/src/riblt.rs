use std::vec::Vec;

use crate::{
    deser::{Encode, Parse},
    leb128, parse,
};

pub(crate) trait Symbol {
    fn zero() -> Self;
    fn xor(&self, other: &Self) -> Self;
    fn hash(&self) -> u64;
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Add = 1,
    Remove = -1,
}

#[derive(Clone, Copy)]
pub(crate) enum Error {
    InvalidDegree = 1,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDegree => f.write_str("InvalidDegree"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub(crate) struct SymbolMapping {
    source_idx: u64,
    coded_idx: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct RandomMapping {
    prng: u64,
    last_idx: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct HashedSymbol<T: Symbol + Copy> {
    symbol: T,
    hash: u64,
}

impl<T: Symbol + Copy> HashedSymbol<T> {
    pub(crate) fn symbol(&self) -> T {
        self.symbol
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct CodedSymbol<T: Symbol + Copy> {
    pub(crate) symbol: T,
    pub(crate) hash: u64,
    pub(crate) count: i64,
}

impl<T: Encode + Symbol + Copy> Encode for CodedSymbol<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.symbol.encode_into(out);
        out.extend(self.hash.to_be_bytes());
        crate::leb128::signed::encode(out, self.count);
    }
}

impl<'a, T: Parse<'a> + Copy + Symbol> Parse<'a> for CodedSymbol<T> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("CodedSymbol", |input| {
            let (input, symbol) = T::parse_in_ctx("symbol", input)?;
            let (input, hash_bytes) = input.parse_in_ctx("hash", parse::arr::<8>)?;
            let hash = u64::from_be_bytes(hash_bytes);
            let (input, count) = input.parse_in_ctx("count", leb128::signed::parse)?;
            Ok((
                input,
                Self {
                    symbol,
                    hash,
                    count,
                },
            ))
        })
    }
}

#[derive(Clone)]
pub(crate) struct Encoder<T: Symbol + Copy> {
    symbols: Vec<HashedSymbol<T>>,
    mappings: Vec<RandomMapping>,
    queue: Vec<SymbolMapping>,
    next_idx: u64,
}

impl<T: Symbol + Copy> Encoder<T> {
    pub(crate) fn next_n_symbols(&mut self, n: u64) -> Vec<CodedSymbol<T>> {
        let mut result = vec![];
        for _ in 0..n {
            let symbol = self.produce_next_coded_symbol();
            result.push(CodedSymbol {
                symbol: symbol.symbol,
                hash: symbol.hash,
                count: symbol.count,
            });
        }
        result
    }
}

#[derive(Clone)]
pub(crate) struct Decoder<T: Symbol + Copy> {
    coded: Vec<CodedSymbol<T>>,
    local: Encoder<T>,
    remote: Encoder<T>,
    window: Encoder<T>,
    decodable: Vec<i64>,
    num_decoded: u64,
}

impl RandomMapping {
    pub(crate) fn next_index(&mut self) -> u64 {
        let r = self.prng.wrapping_mul(0xda942042e4dd58b5);
        self.prng = r;
        self.last_idx = self.last_idx.wrapping_add(
            (((self.last_idx as f64) + 1.5)
                * (((1i64 << 32) as f64) / f64::sqrt((r as f64) + 1.0) - 1.0))
                .ceil() as u64,
        );
        self.last_idx
    }
}

impl<T: Symbol + Copy> CodedSymbol<T> {
    pub(crate) fn apply(&mut self, sym: &HashedSymbol<T>, direction: Direction) {
        self.symbol = self.symbol.xor(&sym.symbol);
        self.hash ^= sym.hash;
        self.count += direction as i64;
    }
}

impl<T: Symbol + Copy> Encoder<T> {
    pub(crate) fn new() -> Self {
        Encoder::<T> {
            symbols: Vec::<HashedSymbol<T>>::new(),
            mappings: Vec::<RandomMapping>::new(),
            queue: Vec::<SymbolMapping>::new(),
            next_idx: 0,
        }
    }

    pub(crate) fn add_hashed_symbol_with_mapping(
        &mut self,
        sym: &HashedSymbol<T>,
        mapp: &RandomMapping,
    ) {
        self.symbols.push(*sym);
        self.mappings.push(*mapp);

        self.queue.push(SymbolMapping {
            source_idx: (self.symbols.len() as u64) - 1,
            coded_idx: mapp.last_idx,
        });

        //  Fix tail
        //
        let mut cur: usize = self.queue.len() - 1;
        while cur > 0 {
            let parent = (cur - 1) / 2;
            if cur == parent || self.queue[parent].coded_idx <= self.queue[cur].coded_idx {
                break;
            }
            self.queue.swap(parent, cur);
            cur = parent;
        }
    }

    pub(crate) fn add_hashed_symbol(&mut self, sym: &HashedSymbol<T>) {
        self.add_hashed_symbol_with_mapping(
            sym,
            &RandomMapping {
                prng: sym.hash,
                last_idx: 0,
            },
        );
    }

    pub(crate) fn add_symbol(&mut self, sym: &T) {
        self.add_hashed_symbol(&HashedSymbol::<T> {
            symbol: *sym,
            hash: sym.hash(),
        });
    }

    pub(crate) fn apply_window(
        &mut self,
        sym: &CodedSymbol<T>,
        direction: Direction,
    ) -> CodedSymbol<T> {
        let mut next_sym = *sym;

        if self.queue.is_empty() {
            self.next_idx += 1;
            return next_sym;
        }

        while self.queue[0].coded_idx == self.next_idx {
            next_sym.apply(&self.symbols[self.queue[0].source_idx as usize], direction);
            self.queue[0].coded_idx = self.mappings[self.queue[0].source_idx as usize].next_index();

            //  Fix head
            //
            let mut cur: usize = 0;
            loop {
                let mut child = cur * 2 + 1;
                if child >= self.queue.len() {
                    break;
                }
                let right_child = child + 1;
                if right_child < self.queue.len()
                    && self.queue[right_child].coded_idx < self.queue[child].coded_idx
                {
                    child = right_child;
                }
                if self.queue[cur].coded_idx <= self.queue[child].coded_idx {
                    break;
                }
                self.queue.swap(cur, child);
                cur = child;
            }
        }

        self.next_idx += 1;
        next_sym
    }

    pub(crate) fn produce_next_coded_symbol(&mut self) -> CodedSymbol<T> {
        self.apply_window(
            &CodedSymbol::<T> {
                symbol: T::zero(),
                hash: 0,
                count: 0,
            },
            Direction::Add,
        )
    }
}

impl<T: Symbol + Copy> Decoder<T> {
    pub(crate) fn new() -> Self {
        Decoder::<T> {
            coded: Vec::<CodedSymbol<T>>::new(),
            local: Encoder::<T>::new(),
            remote: Encoder::<T>::new(),
            window: Encoder::<T>::new(),
            decodable: Vec::<i64>::new(),
            num_decoded: 0,
        }
    }

    pub(crate) fn add_symbol(&mut self, sym: &T) {
        self.window.add_hashed_symbol(&HashedSymbol::<T> {
            symbol: *sym,
            hash: sym.hash(),
        });
    }

    pub(crate) fn add_coded_symbol(&mut self, sym: &CodedSymbol<T>) {
        let mut next_sym = self.window.apply_window(sym, Direction::Remove);
        next_sym = self.remote.apply_window(&next_sym, Direction::Remove);
        next_sym = self.local.apply_window(&next_sym, Direction::Add);

        self.coded.push(next_sym);

        if ((next_sym.count == 1 || next_sym.count == -1)
            && (next_sym.hash == next_sym.symbol.hash()))
            || (next_sym.count == 0 && next_sym.hash == 0)
        {
            self.decodable.push((self.coded.len() as i64) - 1);
        }
    }

    fn apply_new_symbol(&mut self, sym: &HashedSymbol<T>, direction: Direction) -> RandomMapping {
        let mut mapp = RandomMapping {
            prng: sym.hash,
            last_idx: 0,
        };

        while mapp.last_idx < (self.coded.len() as u64) {
            let n = mapp.last_idx as usize;
            self.coded[n].apply(sym, direction);

            if (self.coded[n].count == -1 || self.coded[n].count == 1)
                && self.coded[n].hash == self.coded[n].symbol.hash()
            {
                self.decodable.push(n as i64);
            }

            mapp.next_index();
        }

        mapp
    }

    pub(crate) fn try_decode(&mut self) -> Result<(), Error> {
        let mut didx: usize = 0;

        // self.decodable.len() will increase in apply_new_symbol
        //
        while didx < self.decodable.len() {
            let cidx = self.decodable[didx] as usize;
            let sym = self.coded[cidx];

            match sym.count {
                1 => {
                    let new_sym = HashedSymbol::<T> {
                        symbol: T::zero().xor(&sym.symbol),
                        hash: sym.hash,
                    };

                    let mapp = self.apply_new_symbol(&new_sym, Direction::Remove);
                    self.remote.add_hashed_symbol_with_mapping(&new_sym, &mapp);
                    self.num_decoded += 1;
                }

                -1 => {
                    let new_sym = HashedSymbol::<T> {
                        symbol: T::zero().xor(&sym.symbol),
                        hash: sym.hash,
                    };

                    let mapp = self.apply_new_symbol(&new_sym, Direction::Add);
                    self.local.add_hashed_symbol_with_mapping(&new_sym, &mapp);
                    self.num_decoded += 1;
                }

                0 => {
                    self.num_decoded += 1;
                }

                _ => {
                    return Err(Error::InvalidDegree);
                }
            }

            didx += 1;
        }

        self.decodable.clear();

        Ok(())
    }

    pub(crate) fn decoded(&self) -> bool {
        self.num_decoded == (self.coded.len() as u64)
    }

    pub(crate) fn get_remote_symbols(&self) -> Vec<HashedSymbol<T>> {
        self.remote.symbols.clone()
    }

    pub(crate) fn get_local_symbols(&self) -> Vec<HashedSymbol<T>> {
        self.local.symbols.clone()
    }
}

pub mod doc_and_heads {
    use std::hash::{Hash, Hasher};

    use crate::{
        deser::{Encode, Parse},
        leb128, parse,
        sedimentree::MinimalTreeHash,
        DocumentId,
    };

    #[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize)]
    #[cfg_attr(test, derive(arbitrary::Arbitrary))]
    pub(crate) struct DocAndHeadsSymbol {
        part1: [u8; 32],
        part2: [u8; 32],
    }

    impl Encode for DocAndHeadsSymbol {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend(&self.part1);
            out.extend(&self.part2);
        }
    }

    impl Parse<'_> for DocAndHeadsSymbol {
        fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
            input.parse_in_ctx("RibltSymbol", |input| {
                let (input, part1) = input.parse_in_ctx("part1", parse::arr::<32>)?;
                let (input, part2) = input.parse_in_ctx("part2", parse::arr::<32>)?;
                Ok((input, Self { part1, part2 }))
            })
        }
    }

    impl DocAndHeadsSymbol {
        pub(crate) fn new(doc: &DocumentId, hash: &MinimalTreeHash) -> Self {
            Self {
                part1: *doc.as_bytes(),
                part2: *hash.as_bytes(),
            }
        }
        pub(crate) fn decode(self) -> (DocumentId, MinimalTreeHash) {
            (
                //TODO: return an error
                DocumentId::try_from(self.part1).unwrap(),
                MinimalTreeHash::from(self.part2),
            )
        }
    }

    impl super::Symbol for DocAndHeadsSymbol {
        fn zero() -> Self {
            Self {
                part1: [0; 32],
                part2: [0; 32],
            }
        }

        fn xor(&self, other: &Self) -> Self {
            Self {
                part1: std::array::from_fn(|i| self.part1[i] ^ other.part1[i]),
                part2: std::array::from_fn(|i| self.part2[i] ^ other.part2[i]),
            }
        }

        fn hash(&self) -> u64 {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            self.part1.hash(&mut hasher);
            self.part2.hash(&mut hasher);
            hasher.finish()
        }
    }

    impl DocAndHeadsSymbol {}

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    #[cfg_attr(test, derive(arbitrary::Arbitrary))]
    pub(crate) struct CodedDocAndHeadsSymbol {
        symbol: DocAndHeadsSymbol,
        hash: u64,
        count: i64,
    }

    impl Encode for CodedDocAndHeadsSymbol {
        fn encode_into(&self, out: &mut Vec<u8>) {
            self.symbol.encode_into(out);
            out.extend(self.hash.to_be_bytes());
            leb128::signed::encode(out, self.count);
        }
    }

    impl Parse<'_> for CodedDocAndHeadsSymbol {
        fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
            input.parse_in_ctx("CodedDocAndHeadsSymbol", |input| {
                let (input, symbol) = DocAndHeadsSymbol::parse_in_ctx("symbol", input)?;
                let (input, hash_bytes) = input.parse_in_ctx("hash", parse::arr::<8>)?;
                let hash = u64::from_be_bytes(hash_bytes);
                let (input, count) = input.parse_in_ctx("count", leb128::signed::parse)?;
                Ok((
                    input,
                    Self {
                        symbol,
                        hash,
                        count,
                    },
                ))
            })
        }
    }

    impl CodedDocAndHeadsSymbol {
        pub(crate) fn into_coded(self) -> super::CodedSymbol<DocAndHeadsSymbol> {
            super::CodedSymbol {
                symbol: self.symbol,
                count: self.count,
                hash: self.hash,
            }
        }
    }

    pub(crate) struct Encoder {
        riblt: super::Encoder<DocAndHeadsSymbol>,
    }

    impl Encoder {
        pub(crate) fn new<'a, I: Iterator<Item = (&'a DocumentId, &'a MinimalTreeHash)>>(
            items: I,
        ) -> Self {
            let mut enc = super::Encoder::new();
            for (doc, heads) in items {
                enc.add_symbol(&DocAndHeadsSymbol::new(doc, heads));
            }
            Encoder { riblt: enc }
        }

        pub(crate) fn next_n_symbols(&mut self, n: u64) -> Vec<CodedDocAndHeadsSymbol> {
            let mut result = vec![];
            for _ in 0..n {
                let symbol = self.riblt.produce_next_coded_symbol();
                result.push(CodedDocAndHeadsSymbol {
                    symbol: symbol.symbol,
                    hash: symbol.hash,
                    count: symbol.count,
                });
            }
            result
        }
    }
}
