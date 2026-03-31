//! Proptests comparing ckb-alt-bn128 (new) vs substrate-bn-succinct-rs (original) for G1 point operations.
//!
//! Directly calls sp1-verifier functions instead of maintaining replicas:
//! - `converter::parse_uncompressed_g1` (converter.rs:143-155; called 11× in proof loading)
//! - `converter::parse_compressed_g1` (converter.rs:28-69; called 11× in VK loading)
//! - `converter::g1_to_bytes` (converter.rs:369-381; called ~20× per verification)
//! - `utility::affine_g1_neg` (utility.rs; kzg.rs:188)
//! - `utility::affine_g1_add` (utility.rs; kzg.rs:186)
//! - `utility::affine_g1_sub` (utility.rs; kzg.rs:177)
//! - `utility::affine_g1_msm` with Straus 4-bit windowed Shamir (utility.rs; verify.rs:287, kzg.rs:88, 163, 183)

use bn as sb;
use bn::Group as SbGroup;
use parity_bn as pb;
use parity_bn::Group;
use proptest::prelude::*;
use sp1_verifier::plonk::{
    converter::{g1_to_bytes, parse_compressed_g1, parse_uncompressed_g1},
    utility::{affine_g1_add, affine_g1_msm, affine_g1_neg, affine_g1_sub},
};

fn sb_g1_to_bytes(p: sb::AffineG1) -> [u8; 64] {
    let mut buf = [0u8; 64];
    p.x().to_big_endian(&mut buf[..32]).expect("Fq::to_big_endian");
    p.y().to_big_endian(&mut buf[32..]).expect("Fq::to_big_endian");
    buf
}

fn scalar_bytes(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

/// Generate a canonical uncompressed G1 point (64 bytes: x || y) from a nonzero u64 scalar.
fn g1_uncompressed(n: u64) -> [u8; 64] {
    let scalar = sb::Fr::from_slice(&scalar_bytes(n)).expect("u64 always fits in Fr");
    let pt = sb::G1::one() * scalar;
    let aff =
        sb::AffineG1::from_jacobian(pt).expect("nonzero scalar * generator is never identity");
    sb_g1_to_bytes(aff)
}

fn sb_parse_g1(buf: &[u8; 64]) -> sb::AffineG1 {
    let x = sb::Fq::from_slice(&buf[..32]).expect("valid Fq x");
    let y = sb::Fq::from_slice(&buf[32..]).expect("valid Fq y");
    sb::AffineG1::new(x, y).expect("point is on curve")
}

fn sb_compress_g1(p: sb::AffineG1) -> [u8; 32] {
    let mut buf = [0u8; 32];
    p.x().to_big_endian(&mut buf).expect("Fq::to_big_endian");
    if p.y() > -p.y() {
        buf[0] |= 0xC0;
    } else {
        buf[0] = (buf[0] & 0x3F) | 0x80;
    }
    buf
}

fn sb_parse_compressed_g1(buf: &[u8; 32]) -> Result<sb::AffineG1, &'static str> {
    const MASK: u8 = 0xC0;
    const COMPRESSED_NEGATIVE: u8 = 0xC0;

    let m_data = buf[0] & MASK;
    if m_data == 0 || m_data == 0x40 {
        return Err("invalid flag");
    }

    let mut x_bytes = *buf;
    x_bytes[0] &= !MASK;

    let x = sb::Fq::from_slice(&x_bytes).map_err(|_| "invalid x")?;
    let (smaller_y, larger_y) = sb::AffineG1::get_ys_from_x_unchecked(x).ok_or("no sqrt")?;
    let final_y = if m_data == COMPRESSED_NEGATIVE { larger_y } else { smaller_y };
    sb::AffineG1::new(x, final_y).map_err(|_| "invalid point")
}

// #region parse_uncompressed_g1
proptest! {
    #[test]
    fn parse_uncompressed_g1_equiv(n in 1u64..u64::MAX) {
        let buf = g1_uncompressed(n);
        let pb_pt = parse_uncompressed_g1(&buf).expect("valid uncompressed G1");
        let sb_pt = sb_parse_g1(&buf);
        let pb_bytes = g1_to_bytes(&pb_pt).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_pt)[..]);
    }
}
// #endregion

// #region g1_to_bytes
proptest! {
    #[test]
    fn g1_to_bytes_equiv(n in 1u64..u64::MAX) {
        let sb_fr = sb::Fr::from_slice(&scalar_bytes(n)).expect("u64 fits in Fr");
        let pb_fr = pb::Fr::from_slice(&scalar_bytes(n)).expect("u64 fits in Fr");

        let sb_pt = sb::AffineG1::from_jacobian(sb::G1::one() * sb_fr)
            .expect("nonzero scalar gives non-identity");
        let pb_pt = pb::AffineG1::from_jacobian(pb::G1::one() * pb_fr)
            .expect("nonzero scalar gives non-identity");

        let pb_bytes = g1_to_bytes(&pb_pt).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_pt)[..]);
    }
}
// #endregion

// #region parse_compressed_g1
proptest! {
    #[test]
    fn parse_compressed_g1_equiv(n in 1u64..u64::MAX) {
        let uncompressed = g1_uncompressed(n);
        let sb_pt = sb_parse_g1(&uncompressed);
        let compressed = sb_compress_g1(sb_pt);

        let pb_result = parse_compressed_g1(&compressed);
        let sb_result = sb_parse_compressed_g1(&compressed);

        match (pb_result, sb_result) {
            (Ok(pb_pt), Ok(sb_pt)) => {
                let pb_bytes = g1_to_bytes(&pb_pt).expect("g1_to_bytes");
                prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_pt)[..]);
            }
            (Err(e), Ok(_)) => prop_assert!(false, "ckb-alt-bn128 failed: {e}"),
            (Ok(_), Err(e)) => prop_assert!(false, "substrate-bn failed: {e}"),
            (Err(_), Err(_)) => {}
        }
    }
}
// #endregion

// #region affine_g1_neg
proptest! {
    #[test]
    fn affine_g1_neg_equiv(n in 1u64..u64::MAX) {
        let buf = g1_uncompressed(n);
        let pb_pt = parse_uncompressed_g1(&buf).expect("valid G1");
        let sb_pt = sb_parse_g1(&buf);
        let pb_bytes = g1_to_bytes(&affine_g1_neg(pb_pt)).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(-sb_pt)[..]);
    }
}
// #endregion

// #region affine_g1_add
proptest! {
    #[test]
    fn affine_g1_add_equiv(a in 1u64..u64::MAX / 2, b in u64::MAX / 2..u64::MAX) {
        let buf_a = g1_uncompressed(a);
        let buf_b = g1_uncompressed(b);

        let pb_a = parse_uncompressed_g1(&buf_a).expect("valid G1");
        let pb_b = parse_uncompressed_g1(&buf_b).expect("valid G1");
        let sb_a = sb_parse_g1(&buf_a);
        let sb_b = sb_parse_g1(&buf_b);

        let pb_sum = affine_g1_add(pb_a, pb_b).expect("add should not produce identity");
        let pb_bytes = g1_to_bytes(&pb_sum).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_a + sb_b)[..]);
    }
}
// #endregion

// #region affine_g1_sub
proptest! {
    #[test]
    fn affine_g1_sub_equiv(a in 1u64..u64::MAX / 2, b in u64::MAX / 2..u64::MAX) {
        let buf_a = g1_uncompressed(a);
        let buf_b = g1_uncompressed(b);

        let pb_a = parse_uncompressed_g1(&buf_a).expect("valid G1");
        let pb_b = parse_uncompressed_g1(&buf_b).expect("valid G1");
        let sb_a = sb_parse_g1(&buf_a);
        let sb_b = sb_parse_g1(&buf_b);

        let pb_diff = affine_g1_sub(pb_a, pb_b).expect("sub should not produce identity");
        let pb_bytes = g1_to_bytes(&pb_diff).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_a - sb_b)[..]);
    }
}
// #endregion

// #region affine_g1_msm
proptest! {
    #[test]
    fn affine_g1_msm_multi_equiv(
        point_seeds in proptest::collection::vec(1u64..u64::MAX, 3usize..=13),
        scalar_seeds in proptest::collection::vec(1u64..1000u64, 3usize..=13),
    ) {
        let n = point_seeds.len().min(scalar_seeds.len());

        let mut pb_points = Vec::with_capacity(n);
        let mut sb_points = Vec::with_capacity(n);
        let mut pb_scalars = Vec::with_capacity(n);
        let mut sb_scalars = Vec::with_capacity(n);

        for i in 0..n {
            let buf = g1_uncompressed(point_seeds[i]);
            pb_points.push(parse_uncompressed_g1(&buf).expect("valid G1"));
            sb_points.push(sb_parse_g1(&buf));
            pb_scalars.push(pb::Fr::from_slice(&scalar_bytes(scalar_seeds[i])).expect("valid Fr"));
            sb_scalars.push(sb::Fr::from_slice(&scalar_bytes(scalar_seeds[i])).expect("valid Fr"));
        }

        let pb_result = affine_g1_msm(&pb_points, &pb_scalars);
        let sb_result = sb::AffineG1::msm(&sb_points, &sb_scalars);
        let pb_bytes = g1_to_bytes(&pb_result).expect("g1_to_bytes");
        prop_assert_eq!(pb_bytes.as_slice(), &sb_g1_to_bytes(sb_result)[..]);
    }
}
// #endregion
