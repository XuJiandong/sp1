//! Proptests comparing parity-bn (new) vs substrate-bn-succinct-rs (original) for G1 point operations.
//!
//! Changed operations covered:
//! - `uncompressed_bytes_to_g1_point` → `parse_uncompressed_g1` (converter.rs:143-155; called 11× in load_plonk_proof_from_bytes)
//! - `unchecked_compressed_x_to_g1_point` → `parse_compressed_g1` (converter.rs:28-69; called 11× in load_plonk_verifying_key_from_bytes)
//! - `g1_to_bytes` serialization via `Fq::to_big_endian` (converter.rs:369-381; called ~20× per verification in bind_public_data and derive_randomness)
//! - `-AffineG1` → `affine_g1_neg` (utility.rs; kzg.rs:188)
//! - `AffineG1 + AffineG1` → `affine_g1_add` (utility.rs; kzg.rs:186)
//! - `AffineG1 - AffineG1` → `affine_g1_sub` (utility.rs; kzg.rs:177)
//! - `AffineG1::msm` → `affine_g1_msm` (utility.rs; verify.rs:287, kzg.rs:88, 163, 183)

use bn as sb;
use bn::Group as SbGroup;
use parity_bn as pb;
use parity_bn::Group;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Serialization helpers — mirrors g1_to_bytes (converter.rs:369-381)
// ---------------------------------------------------------------------------

fn pb_g1_to_bytes(p: pb::AffineG1) -> [u8; 64] {
    let mut buf = [0u8; 64];
    p.x().to_big_endian(&mut buf[..32]).expect("Fq::to_big_endian");
    p.y().to_big_endian(&mut buf[32..]).expect("Fq::to_big_endian");
    buf
}

fn sb_g1_to_bytes(p: sb::AffineG1) -> [u8; 64] {
    let mut buf = [0u8; 64];
    p.x().to_big_endian(&mut buf[..32]).expect("Fq::to_big_endian");
    p.y().to_big_endian(&mut buf[32..]).expect("Fq::to_big_endian");
    buf
}

// ---------------------------------------------------------------------------
// Point generation helpers
// ---------------------------------------------------------------------------

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

fn pb_parse_g1(buf: &[u8; 64]) -> pb::AffineG1 {
    let x = pb::Fq::from_slice(&buf[..32]).expect("valid Fq x");
    let y = pb::Fq::from_slice(&buf[32..]).expect("valid Fq y");
    pb::AffineG1::new(x, y).expect("point is on curve")
}

fn sb_parse_g1(buf: &[u8; 64]) -> sb::AffineG1 {
    let x = sb::Fq::from_slice(&buf[..32]).expect("valid Fq x");
    let y = sb::Fq::from_slice(&buf[32..]).expect("valid Fq y");
    sb::AffineG1::new(x, y).expect("point is on curve")
}

// ---------------------------------------------------------------------------
// Replicated parity-bn wrappers (mirrors utility.rs)
// ---------------------------------------------------------------------------

fn pb_neg(p: pb::AffineG1) -> pb::AffineG1 {
    pb::AffineG1::from_jacobian(-pb::G1::from(p)).expect("negation of non-identity is non-identity")
}

fn pb_add(a: pb::AffineG1, b: pb::AffineG1) -> Option<pb::AffineG1> {
    pb::AffineG1::from_jacobian(pb::G1::from(a) + pb::G1::from(b))
}

fn pb_sub(a: pb::AffineG1, b: pb::AffineG1) -> Option<pb::AffineG1> {
    pb::AffineG1::from_jacobian(pb::G1::from(a) - pb::G1::from(b))
}

fn pb_msm(points: &[pb::AffineG1], scalars: &[pb::Fr]) -> Option<pb::AffineG1> {
    let mut acc = pb::G1::zero();
    for (p, s) in points.iter().zip(scalars.iter()) {
        acc = acc + pb::G1::from(*p) * *s;
    }
    pb::AffineG1::from_jacobian(acc)
}

// ---------------------------------------------------------------------------
// Fq sqrt for parity-bn (BN254: p ≡ 3 mod 4 → sqrt(a) = a^((p+1)/4))
// ---------------------------------------------------------------------------

fn pb_fq_sqrt(a: pb::Fq) -> Option<pb::Fq> {
    let exp = pb::arith::U256::from([
        0x4f082305b61f3f52u64,
        0x65e05aa45a1c72a3u64,
        0x6e14116da0605617u64,
        0x0c19139cb84c680au64,
    ]);
    let exp_fq = pb::Fq::from_u256(exp).expect("(p+1)/4 < p");
    let candidate = a.pow(exp_fq);
    if candidate * candidate == a {
        Some(candidate)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Compressed G1 parsing replicas (mirrors converter.rs:28-69)
// ---------------------------------------------------------------------------

fn pb_parse_compressed_g1(buf: &[u8; 32]) -> Result<pb::AffineG1, &'static str> {
    const MASK: u8 = 0xC0;
    const COMPRESSED_NEGATIVE: u8 = 0xC0;
    const COMPRESSED_INFINITY: u8 = 0x40;

    let m_data = buf[0] & MASK;
    if m_data == 0 || m_data == COMPRESSED_INFINITY {
        return Err("invalid flag");
    }

    let mut x_bytes = *buf;
    x_bytes[0] &= !MASK;

    let x = pb::Fq::from_slice(&x_bytes).map_err(|_| "invalid x")?;
    let y_sq = x * x * x + pb::G1::b();
    let y = pb_fq_sqrt(y_sq).ok_or("no sqrt")?;
    let neg_y = -y;

    let y_u256 = y.into_u256();
    let neg_y_u256 = neg_y.into_u256();

    let final_y = if m_data == COMPRESSED_NEGATIVE {
        if y_u256 > neg_y_u256 {
            y
        } else {
            neg_y
        }
    } else {
        if y_u256 > neg_y_u256 {
            neg_y
        } else {
            y
        }
    };

    pb::AffineG1::new(x, final_y).map_err(|_| "invalid point")
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

// ---------------------------------------------------------------------------
// Tests: parse_uncompressed_g1 (converter.rs:143-155)
// Called 11× in load_plonk_proof_from_bytes for lro[0..2], h[0..2], z,
// batched_proof.h, z_shifted_opening.h, and bsb22_commitments.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn parse_uncompressed_g1_equiv(n in 1u64..u64::MAX) {
        let uncompressed = g1_uncompressed(n);
        let pb_pt = pb_parse_g1(&uncompressed);
        let sb_pt = sb_parse_g1(&uncompressed);
        prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_pt));
    }
}

// ---------------------------------------------------------------------------
// Tests: g1_to_bytes (converter.rs:369-381)
// Serializes AffineG1 → 64 bytes via Fq::to_big_endian for x and y.
// Called ~20× per verification in bind_public_data (vk G1 points) and
// derive_randomness (proof G1 points). Exercised here on scalar multiplication
// results, which is the primary source of G1 points in the VK and proof.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn g1_to_bytes_equiv(n in 1u64..u64::MAX) {
        let sb_fr = sb::Fr::from_slice(&scalar_bytes(n)).expect("u64 fits in Fr");
        let pb_fr = pb::Fr::from_slice(&scalar_bytes(n)).expect("u64 fits in Fr");

        let sb_pt = sb::AffineG1::from_jacobian(sb::G1::one() * sb_fr)
            .expect("nonzero scalar gives non-identity");
        let pb_pt = pb::AffineG1::from_jacobian(pb::G1::one() * pb_fr)
            .expect("nonzero scalar gives non-identity");

        prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_pt));
    }
}

// ---------------------------------------------------------------------------
// Tests: parse_compressed_g1 (converter.rs:28-69)
// Called 11× in load_plonk_verifying_key_from_bytes for s[0..2], ql, qr, qm,
// qo, qk, qcp[0], and the KZG g1 point.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn parse_compressed_g1_equiv(n in 1u64..u64::MAX) {
        let uncompressed = g1_uncompressed(n);
        let sb_pt = sb_parse_g1(&uncompressed);
        let compressed = sb_compress_g1(sb_pt);

        let pb_result = pb_parse_compressed_g1(&compressed);
        let sb_result = sb_parse_compressed_g1(&compressed);

        match (pb_result, sb_result) {
            (Ok(pb_pt), Ok(sb_pt)) => {
                prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_pt));
            }
            (Err(e), Ok(_)) => prop_assert!(false, "parity-bn failed: {e}"),
            (Ok(_), Err(e)) => prop_assert!(false, "substrate-bn failed: {e}"),
            (Err(_), Err(_)) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: affine_g1_neg (utility.rs; kzg.rs:188)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn affine_g1_neg_equiv(n in 1u64..u64::MAX) {
        let buf = g1_uncompressed(n);
        let pb_pt = pb_parse_g1(&buf);
        let sb_pt = sb_parse_g1(&buf);
        prop_assert_eq!(pb_g1_to_bytes(pb_neg(pb_pt)), sb_g1_to_bytes(-sb_pt));
    }
}

// ---------------------------------------------------------------------------
// Tests: affine_g1_add (utility.rs; kzg.rs:186)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn affine_g1_add_equiv(a in 1u64..u64::MAX / 2, b in u64::MAX / 2..u64::MAX) {
        let buf_a = g1_uncompressed(a);
        let buf_b = g1_uncompressed(b);

        let pb_a = pb_parse_g1(&buf_a);
        let pb_b = pb_parse_g1(&buf_b);
        let sb_a = sb_parse_g1(&buf_a);
        let sb_b = sb_parse_g1(&buf_b);

        match pb_add(pb_a, pb_b) {
            Some(pb_pt) => prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_a + sb_b)),
            None => prop_assert!(false, "unexpected identity sum for scalars {a} and {b}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: affine_g1_sub (utility.rs; kzg.rs:177)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn affine_g1_sub_equiv(a in 1u64..u64::MAX / 2, b in u64::MAX / 2..u64::MAX) {
        let buf_a = g1_uncompressed(a);
        let buf_b = g1_uncompressed(b);

        let pb_a = pb_parse_g1(&buf_a);
        let pb_b = pb_parse_g1(&buf_b);
        let sb_a = sb_parse_g1(&buf_a);
        let sb_b = sb_parse_g1(&buf_b);

        match pb_sub(pb_a, pb_b) {
            Some(pb_pt) => prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_a - sb_b)),
            None => prop_assert!(false, "unexpected identity difference for scalars {a} and {b}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: affine_g1_msm (utility.rs; verify.rs:287, kzg.rs:88, 163, 183)
//
// verify.rs:287 passes ~13 points (qcp + ql,qr,qm,qo,qk,s[2],z,h[0],h[1],h[2]).
// kzg.rs:88 passes ~8 points (digests_to_fold).
// kzg.rs:163,183 pass 2 points each (batch verify quotients).
// Testing with 3–13 points exercises the accumulation loop at realistic scale.
// ---------------------------------------------------------------------------

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
            pb_points.push(pb_parse_g1(&buf));
            sb_points.push(sb_parse_g1(&buf));
            pb_scalars.push(pb::Fr::from_slice(&scalar_bytes(scalar_seeds[i])).expect("valid Fr"));
            sb_scalars.push(sb::Fr::from_slice(&scalar_bytes(scalar_seeds[i])).expect("valid Fr"));
        }

        let sb_result = sb::AffineG1::msm(&sb_points, &sb_scalars);
        match pb_msm(&pb_points, &pb_scalars) {
            Some(pb_pt) => prop_assert_eq!(pb_g1_to_bytes(pb_pt), sb_g1_to_bytes(sb_result)),
            None => prop_assert!(false, "unexpected identity MSM result"),
        }
    }
}
