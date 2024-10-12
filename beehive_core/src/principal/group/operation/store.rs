// use super::delegation::Delegation;
// use crate::crypto::hash::Hash;
//
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct CausalOp<'a> {
//     pub hash: &'a Hash<Delegation<'a, T>>,
//     pub op: &'a Delegation<'a, T>,
//     pub history: Levels<'a>,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct Levels<'a> {
//     // 256^0 = 1
//     pub no_zeros: Vec<&'a CausalOp<'a>>,
//
//     // 256^1 = 256
//     pub one_zero: Vec<&'a CausalOp<'a>>,
//
//     // 256^2 = 65,536
//     pub two_zeros: Vec<&'a CausalOp<'a>>,
//
//     // 256^3 = 16,777,216
//     pub three_zeros: Vec<&'a CausalOp<'a>>,
//
//     // 256^4 = 4,294,967,296
//     pub four_zeros: Vec<&'a CausalOp<'a>>,
// }
//
// impl<'a> Levels<'a> {
//     pub fn find_position(&self, hash: &Hash<Delegation>) -> Option<(u8, usize)> {
//         let level = match hash.trailing_zero_bytes() {
//             0 => &self.no_zeros,
//             1 => &self.one_zero,
//             2 => &self.two_zeros,
//             3 => &self.three_zeros,
//             _ => &self.four_zeros,
//         };
//
//         level
//             .iter()
//             .position(|op| op.hash == hash)
//             .map(|pos| (hash.trailing_zero_bytes(), pos))
//     }
//
//     pub fn contains(&self, hash: &Hash<Delegation>) -> bool {
//         let level = match hash.trailing_zero_bytes() {
//             0 => &self.no_zeros,
//             1 => &self.one_zero,
//             2 => &self.two_zeros,
//             3 => &self.three_zeros,
//             _ => &self.four_zeros,
//         };
//
//         level.iter().find(|op| op.hash == hash).is_some()
//     }
// }
//
// impl<'a> PartialOrd for CausalOp<'a> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         if self.hash == other.hash {
//             return Some(std::cmp::Ordering::Equal);
//         }
//
//         //
//
//         // FIXME self.history.common_ancestor(other)
//         todo!()
//
//         // Is left hash in right, or is right in left?
//     }
// }
