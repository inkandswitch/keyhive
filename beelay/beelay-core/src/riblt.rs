use std::vec::Vec;

pub(crate) trait Symbol {
    fn zero() -> Self;
    fn xor(&self, other: &Self) -> Self;
    fn hash(&self) -> u64;
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    ADD = 1,
    REMOVE = -1,
}

#[derive(Clone, Copy)]
pub(crate) enum Error {
    InvalidDegree = 1,
    InvalidSize = 2,
    DecodeFailed = 3,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDegree => f.write_str("InvalidDegree"),
            Error::InvalidSize => f.write_str("InvalidSize"),
            Error::DecodeFailed => f.write_str("DecodeFailed"),
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

#[derive(Clone, Copy)]
pub(crate) struct CodedSymbol<T: Symbol + Copy> {
    pub(crate) symbol: T,
    pub(crate) hash: u64,
    pub(crate) count: i64,
}

#[derive(Clone)]
pub(crate) struct Encoder<T: Symbol + Copy> {
    symbols: Vec<HashedSymbol<T>>,
    mappings: Vec<RandomMapping>,
    queue: Vec<SymbolMapping>,
    next_idx: u64,
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
        return self.last_idx;
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
        return Encoder::<T> {
            symbols: Vec::<HashedSymbol<T>>::new(),
            mappings: Vec::<RandomMapping>::new(),
            queue: Vec::<SymbolMapping>::new(),
            next_idx: 0,
        };
    }

    pub(crate) fn reset(&mut self) {
        self.symbols.clear();
        self.mappings.clear();
        self.queue.clear();
        self.next_idx = 0;
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
        return next_sym;
    }

    pub(crate) fn produce_next_coded_symbol(&mut self) -> CodedSymbol<T> {
        return self.apply_window(
            &CodedSymbol::<T> {
                symbol: T::zero(),
                hash: 0,
                count: 0,
            },
            Direction::ADD,
        );
    }
}

impl<T: Symbol + Copy> Decoder<T> {
    pub(crate) fn new() -> Self {
        return Decoder::<T> {
            coded: Vec::<CodedSymbol<T>>::new(),
            local: Encoder::<T>::new(),
            remote: Encoder::<T>::new(),
            window: Encoder::<T>::new(),
            decodable: Vec::<i64>::new(),
            num_decoded: 0,
        };
    }

    pub(crate) fn reset(&mut self) {
        self.coded.clear();
        self.local.reset();
        self.remote.reset();
        self.window.reset();
        self.decodable.clear();
        self.num_decoded = 0;
    }

    pub(crate) fn add_symbol(&mut self, sym: &T) {
        self.window.add_hashed_symbol(&HashedSymbol::<T> {
            symbol: *sym,
            hash: sym.hash(),
        });
    }

    pub(crate) fn add_coded_symbol(&mut self, sym: &CodedSymbol<T>) {
        let mut next_sym = self.window.apply_window(sym, Direction::REMOVE);
        next_sym = self.remote.apply_window(&next_sym, Direction::REMOVE);
        next_sym = self.local.apply_window(&next_sym, Direction::ADD);

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
            self.coded[n].apply(&sym, direction);

            if (self.coded[n].count == -1 || self.coded[n].count == 1)
                && self.coded[n].hash == self.coded[n].symbol.hash()
            {
                self.decodable.push(n as i64);
            }

            mapp.next_index();
        }

        return mapp;
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

                    let mapp = self.apply_new_symbol(&new_sym, Direction::REMOVE);
                    self.remote.add_hashed_symbol_with_mapping(&new_sym, &mapp);
                    self.num_decoded += 1;
                }

                -1 => {
                    let new_sym = HashedSymbol::<T> {
                        symbol: T::zero().xor(&sym.symbol),
                        hash: sym.hash,
                    };

                    let mapp = self.apply_new_symbol(&new_sym, Direction::ADD);
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

        return Ok(());
    }

    pub(crate) fn decoded(&self) -> bool {
        return self.num_decoded == (self.coded.len() as u64);
    }

    pub(crate) fn get_remote_symbols(&self) -> Vec<HashedSymbol<T>> {
        return self.remote.symbols.clone();
    }

    pub(crate) fn get_local_symbols(&self) -> Vec<HashedSymbol<T>> {
        return self.local.symbols.clone();
    }
}

pub mod doc_and_heads {
    use std::hash::{Hash, Hasher};

    use crate::{leb128, parse, sedimentree::MinimalTreeHash, DocumentId};

    #[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize)]
    #[cfg_attr(test, derive(arbitrary::Arbitrary))]
    pub(crate) struct DocAndHeadsSymbol {
        part1: [u8; 16],
        part2: [u8; 32],
    }

    impl DocAndHeadsSymbol {
        pub(crate) fn new(doc: &DocumentId, hash: &MinimalTreeHash) -> Self {
            Self {
                part1: doc.as_bytes().clone(),
                part2: hash.as_bytes().clone(),
            }
        }
        pub(crate) fn decode(self) -> (DocumentId, MinimalTreeHash) {
            (
                DocumentId::from(self.part1),
                MinimalTreeHash::from(self.part2),
            )
        }
    }

    impl super::Symbol for DocAndHeadsSymbol {
        fn zero() -> Self {
            Self {
                part1: [0; 16],
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

    impl DocAndHeadsSymbol {
        pub(crate) fn parse(
            input: parse::Input<'_>,
        ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
            input.with_context("RibltSymbol", |input| {
                let (input, part1) = parse::arr::<16>(input)?;
                let (input, part2) = parse::arr::<32>(input)?;
                Ok((input, Self { part1, part2 }))
            })
        }

        pub(crate) fn encode(&self, out: &mut Vec<u8>) {
            out.extend(&self.part1);
            out.extend(&self.part2);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    #[cfg_attr(test, derive(arbitrary::Arbitrary))]
    pub(crate) struct CodedDocAndHeadsSymbol {
        symbol: DocAndHeadsSymbol,
        hash: u64,
        count: i64,
    }

    impl CodedDocAndHeadsSymbol {
        pub(crate) fn parse(
            input: parse::Input<'_>,
        ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
            let (input, symbol) = DocAndHeadsSymbol::parse(input)?;
            let (input, hash_bytes) = parse::arr::<8>(input)?;
            let hash = u64::from_be_bytes(hash_bytes);
            let (input, count) = leb128::signed::parse(input)?;
            Ok((
                input,
                Self {
                    symbol,
                    hash,
                    count,
                },
            ))
        }

        pub(crate) fn encode(&self, out: &mut Vec<u8>) {
            self.symbol.encode(out);
            out.extend(self.hash.to_be_bytes());
            leb128::signed::encode(out, self.count);
        }

        pub(crate) fn into_coded(&self) -> super::CodedSymbol<DocAndHeadsSymbol> {
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
        pub(crate) fn new(snapshot: &crate::snapshots::Snapshot) -> Self {
            let mut enc = super::Encoder::new();
            for (doc, heads) in snapshot.our_docs_2() {
                enc.add_symbol(&DocAndHeadsSymbol::new(&doc, &heads));
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
