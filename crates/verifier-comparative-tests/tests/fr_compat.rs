//! Proptests comparing parity-bn (new) vs substrate-bn-succinct-rs (original) for Fr field operations and U256 byte serialization.
//!
//! Changed operations covered:
//! - `u256.to_bytes_be()` → `utility::u256_to_bytes_be` (verify.rs:102, 241)
//! - `Fr::from_bytes_be_mod_order(bytes)` → `fr_from_bytes_be_mod_order` (verify.rs:152, 386; kzg.rs:74)
//! - `fr.into_u256().to_bytes_be()` → `u256_to_bytes_be(&fr.into_u256())` (verify.rs:312, 362; kzg.rs:56, 64, 115)

use bn as sb;
use parity_bn as pb;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Replicated parity-bn utility functions (mirrors utility.rs)
// ---------------------------------------------------------------------------

/// Replica of `utility::u256_to_bytes_be`.
fn pb_u256_to_bytes_be(u: &pb::arith::U256) -> [u8; 32] {
    let mut buf = [0u8; 32];
    u.to_big_endian(&mut buf).expect("32-byte buffer always succeeds");
    buf
}

/// Replica of `utility::fr_from_bytes_be_mod_order`.
fn pb_fr_from_bytes_be_mod_order(bytes: &[u8]) -> pb::Fr {
    let mut buf = [0u8; 64];
    if bytes.len() >= 64 {
        buf.copy_from_slice(&bytes[bytes.len() - 64..]);
    } else {
        buf[64 - bytes.len()..].copy_from_slice(bytes);
    }
    pb::Fr::interpret(&buf)
}

/// Construct a 32-byte big-endian representation of a u64.
fn u64_to_be32(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Tests: u256_to_bytes_be (verify.rs:102, 241)
//
// `U256::from(vk.size as u64)` and `U256::from(vk.size + 2)` are serialized
// via `u256_to_bytes_be` and fed to `Fr::from_slice` to produce Fr exponents.
// ---------------------------------------------------------------------------

proptest! {
    /// U256 values constructed from u64 (the only form used in the verifier)
    /// serialize identically via both libraries.
    #[test]
    fn u256_to_bytes_be_equiv(n in any::<u64>()) {
        let pb_u256 = pb::arith::U256::from(n);
        let sb_u256 = sb::arith::U256::from(n);
        prop_assert_eq!(pb_u256_to_bytes_be(&pb_u256), sb_u256.to_bytes_be());
    }
}

// ---------------------------------------------------------------------------
// Tests: fr_from_bytes_be_mod_order (verify.rs:152, 386; kzg.rs:74)
//
// Called with:
//   - 32-byte SHA-256 output (Fiat-Shamir challenges via derive_randomness)
//   - 48-byte output from hash_to_field.sum() (BSB22 commitment hashing)
// ---------------------------------------------------------------------------

proptest! {
    /// 32-byte inputs: the Fiat-Shamir challenge path (derive_randomness at
    /// verify.rs:386 and kzg.rs:74 passes a 32-byte SHA-256 digest).
    #[test]
    fn fr_from_bytes_be_mod_order_32bytes(bytes in any::<[u8; 32]>()) {
        let pb_fr = pb_fr_from_bytes_be_mod_order(&bytes);
        let sb_fr = sb::Fr::from_bytes_be_mod_order(&bytes)
            .expect("substrate-bn Fr::from_bytes_be_mod_order should not fail");
        prop_assert_eq!(pb_fr_to_bytes(pb_fr), sb_fr_to_bytes(sb_fr));
    }

    /// 48-byte inputs: the actual output length of `hash_to_field.sum()` used
    /// for BSB22 commitment hashing at verify.rs:152.
    /// (`l = 16 + 32 = 48`, so `len_in_bytes = 1 * 48`.)
    #[test]
    fn fr_from_bytes_be_mod_order_48bytes(bytes in any::<[u8; 48]>()) {
        let pb_fr = pb_fr_from_bytes_be_mod_order(&bytes);
        let sb_fr = sb::Fr::from_bytes_be_mod_order(&bytes)
            .expect("substrate-bn Fr::from_bytes_be_mod_order should not fail");
        prop_assert_eq!(pb_fr_to_bytes(pb_fr), sb_fr_to_bytes(sb_fr));
    }
}

// ---------------------------------------------------------------------------
// Tests: fr.into_u256() transcript serialization (verify.rs:312, 362;
//        kzg.rs:56, 64, 115)
//
// The verifier feeds Fr values into the Fiat-Shamir transcript via:
//   utility::u256_to_bytes_be(&fr.into_u256())
// for `zu`, `public_input`, `point`, `claimed_value`, and `gamma`.
//
// `into_u256()` must return the canonical (non-Montgomery) representation so
// that the serialized bytes match gnark's expected transcript input.
// This test verifies that substrate-bn's `Fr::into_u256()` roundtrips canonical
// bytes, documenting the semantics that ckb-alt-bn128 must also satisfy.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn fr_into_u256_canonical_roundtrip(n in 1u64..u64::MAX) {
        let canonical = u64_to_be32(n);
        let sb_fr = sb::Fr::from_slice(&canonical).expect("u64 fits in Fr");
        // into_u256() must return canonical U256; combined with u256_to_bytes_be
        // this must recover the original bytes
        let result = sb_fr.into_u256().to_bytes_be();
        prop_assert_eq!(result, canonical);
    }
}
