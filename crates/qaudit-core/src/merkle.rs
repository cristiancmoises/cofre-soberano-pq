//! Merkle Mountain Range (MMR) over BLAKE3.
//!
//! Append-only binary Merkle tree optimized for streaming logs. The full tree
//! is never materialized: only a frontier of O(log n) hashes is kept in memory.
//!
//! Hash domains follow RFC 6962 conventions:
//! - Leaves: `BLAKE3(0x00 || content_hash)`
//! - Nodes:  `BLAKE3(0x01 || left || right)`
//!
//! The root of an unbalanced tree is computed by "bagging" frontier peaks from
//! the largest subtree down to the smallest:
//! `root = node(p_k, node(p_{k-1}, ..., node(p_1, p_0)))`
//! where `p_i` is the peak covering `2^i` leaves.

use serde::{Deserialize, Serialize};

/// 256-bit hash output.
pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Domain-separated hash of a leaf payload.
#[must_use]
pub fn leaf_hash(content: &[u8; 32]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(content);
    h.finalize().into()
}

/// Domain-separated hash of an internal node.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Incremental binary Merkle tree (MMR).
///
/// Memory usage is `O(log n)` for the frontier vector. Supports up to `2^64`
/// leaves before counter overflow.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MerkleTree {
    /// Total number of leaves appended.
    count: u64,
    /// Frontier peaks. `frontier[i] = Some(h)` means there is a perfect subtree
    /// of `2^i` leaves rooted at `h` that has not yet been combined with a
    /// sibling. `None` means that level is currently empty.
    frontier: Vec<Option<Hash>>,
}

impl MerkleTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves in the tree.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.count
    }

    /// `true` if no leaves have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Append a content hash and return the new root.
    pub fn append(&mut self, content: &[u8; 32]) -> Hash {
        let mut carry = leaf_hash(content);
        let mut i = 0;
        loop {
            if i >= self.frontier.len() {
                self.frontier.push(Some(carry));
                break;
            }
            match self.frontier[i].take() {
                None => {
                    self.frontier[i] = Some(carry);
                    break;
                }
                Some(left) => {
                    carry = node_hash(&left, &carry);
                    i += 1;
                }
            }
        }
        self.count += 1;
        self.root()
    }

    /// Compute the current root by bagging the frontier peaks.
    ///
    /// Empty tree returns the all-zero hash.
    #[must_use]
    pub fn root(&self) -> Hash {
        if self.count == 0 {
            return [0u8; 32];
        }
        // Walk from level 0 upward. Combine each present peak with the
        // accumulator, where the higher-level peak is on the left (it covers
        // more leaves, which lie to the left in append order).
        let mut acc: Option<Hash> = None;
        for h in self.frontier.iter().flatten() {
            acc = Some(match acc {
                None => *h,
                Some(a) => node_hash(h, &a),
            });
        }
        acc.unwrap_or([0u8; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        b
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let t = MerkleTree::new();
        assert_eq!(t.root(), [0u8; 32]);
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let mut t = MerkleTree::new();
        let c = leaf(7);
        let root = t.append(&c);
        assert_eq!(root, leaf_hash(&c));
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
    }

    #[test]
    fn two_leaves_root_is_node_of_leaf_hashes() {
        let mut t = MerkleTree::new();
        let a = leaf(1);
        let b = leaf(2);
        t.append(&a);
        let root = t.append(&b);
        let expected = node_hash(&leaf_hash(&a), &leaf_hash(&b));
        assert_eq!(root, expected);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn three_leaves_bagging_correct() {
        // Tree of 3 leaves: perfect subtree of 2 (a,b) + singleton c.
        // Root = node( node(la,lb), lc )
        let mut t = MerkleTree::new();
        let a = leaf(1);
        let b = leaf(2);
        let c = leaf(3);
        t.append(&a);
        t.append(&b);
        let root = t.append(&c);
        let expected = node_hash(&node_hash(&leaf_hash(&a), &leaf_hash(&b)), &leaf_hash(&c));
        assert_eq!(root, expected);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn four_leaves_perfect_tree() {
        let mut t = MerkleTree::new();
        let xs: Vec<_> = (1..=4).map(leaf).collect();
        for x in &xs {
            t.append(x);
        }
        let l01 = node_hash(&leaf_hash(&xs[0]), &leaf_hash(&xs[1]));
        let l23 = node_hash(&leaf_hash(&xs[2]), &leaf_hash(&xs[3]));
        let expected = node_hash(&l01, &l23);
        assert_eq!(t.root(), expected);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn five_leaves_bag_4_plus_1() {
        // Perfect subtree of 4 (a,b,c,d) + singleton e.
        // Root = node( root4, le )
        let mut t = MerkleTree::new();
        let xs: Vec<_> = (1..=5).map(leaf).collect();
        for x in &xs {
            t.append(x);
        }
        let l01 = node_hash(&leaf_hash(&xs[0]), &leaf_hash(&xs[1]));
        let l23 = node_hash(&leaf_hash(&xs[2]), &leaf_hash(&xs[3]));
        let root4 = node_hash(&l01, &l23);
        let expected = node_hash(&root4, &leaf_hash(&xs[4]));
        assert_eq!(t.root(), expected);
        assert_eq!(t.len(), 5);
    }

    #[test]
    fn root_changes_on_every_append() {
        let mut t = MerkleTree::new();
        let mut prev = t.root();
        for i in 0..200u32 {
            let r = t.append(&leaf(i));
            assert_ne!(r, prev, "root collision at i={i}");
            prev = r;
        }
        assert_eq!(t.len(), 200);
    }

    #[test]
    fn append_is_deterministic() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0..1000u32 {
            let l = leaf(i);
            assert_eq!(a.append(&l), b.append(&l));
        }
        assert_eq!(a, b);
    }

    #[test]
    fn cbor_roundtrip_of_tree_state() {
        let mut t = MerkleTree::new();
        for i in 0..37u32 {
            t.append(&leaf(i));
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&t, &mut bytes).unwrap();
        let back: MerkleTree = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(t, back);
        assert_eq!(t.root(), back.root());
    }
}
