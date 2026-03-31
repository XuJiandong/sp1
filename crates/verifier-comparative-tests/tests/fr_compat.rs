//! Proptests comparing ckb-alt-bn128 (new) vs substrate-bn-succinct-rs (original) for Fr field operations and U256 byte serialization.
//!
//! Operations covered (directly calling sp1-verifier functions):
//! - `utility::u256_to_bytes_be` (verify.rs:102, 241)
//! - `utility::fr_from_bytes_be_mod_order` (verify.rs:152, 386; kzg.rs:74)
//! - `fr.into_u256()` canonical semantics (verify.rs:312, 362; kzg.rs:56, 64, 115)

use bn as sb;
use parity_bn as pb;
use proptest::prelude::*;
use sp1_verifier::plonk::utility::{fr_from_bytes_be_mod_order, u256_to_bytes_be};

fn pb_fr_to_bytes(f: pb::Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    f.to_big_endian(&mut buf).expect("Fr::to_big_endian never fails");
    buf
}

fn sb_fr_to_bytes(f: sb::Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    f.to_big_endian(&mut buf).expect("Fr::to_big_endian never fails");
    buf
}

fn u64_to_be32(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

// #region u256_to_bytes_be
proptest! {
    /// U256 values constructed from u64 (the only form used in the verifier)
    /// serialize identically via both libraries.
    #[test]
    fn u256_to_bytes_be_equiv(n in any::<u64>()) {
        let pb_u256 = pb::arith::U256::from(n);
        let sb_u256 = sb::arith::U256::from(n);
        prop_assert_eq!(u256_to_bytes_be(&pb_u256), sb_u256.to_bytes_be());
    }
}
// #endregion

// #region fr_from_bytes_be_mod_order
proptest! {
    /// 32-byte inputs: the Fiat-Shamir challenge path (derive_randomness at
    /// verify.rs:386 and kzg.rs:74 passes a 32-byte SHA-256 digest).
    #[test]
    fn fr_from_bytes_be_mod_order_32bytes(bytes in any::<[u8; 32]>()) {
        let pb_fr = fr_from_bytes_be_mod_order(&bytes);
        let sb_fr = sb::Fr::from_bytes_be_mod_order(&bytes)
            .expect("substrate-bn Fr::from_bytes_be_mod_order should not fail");
        prop_assert_eq!(pb_fr_to_bytes(pb_fr), sb_fr_to_bytes(sb_fr));
    }

    /// 48-byte inputs: the actual output length of `hash_to_field.sum()` used
    /// for BSB22 commitment hashing at verify.rs:152.
    #[test]
    fn fr_from_bytes_be_mod_order_48bytes(bytes in any::<[u8; 48]>()) {
        let pb_fr = fr_from_bytes_be_mod_order(&bytes);
        let sb_fr = sb::Fr::from_bytes_be_mod_order(&bytes)
            .expect("substrate-bn Fr::from_bytes_be_mod_order should not fail");
        prop_assert_eq!(pb_fr_to_bytes(pb_fr), sb_fr_to_bytes(sb_fr));
    }
}
// #endregion

// #region fr_into_u256 canonical roundtrip
proptest! {
    #[test]
    fn fr_into_u256_canonical_roundtrip(n in 1u64..u64::MAX) {
        let canonical = u64_to_be32(n);
        let sb_fr = sb::Fr::from_slice(&canonical).expect("u64 fits in Fr");
        let result = sb_fr.into_u256().to_bytes_be();
        prop_assert_eq!(result, canonical);
    }
}
// #endregion
