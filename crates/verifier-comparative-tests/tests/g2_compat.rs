//! Proptests comparing parity-bn (new) vs substrate-bn-succinct-rs (original) for G2 point parsing.
//!
//! Changed operation covered:
//! - `unchecked_compressed_x_to_g2_point` → `parse_compressed_g2` (converter.rs:76-140;
//!   called 2× in load_plonk_verifying_key_from_bytes for g2_0 and g2_1 of the KZG key)
//!
//! # Convention note
//!
//! `parse_compressed_g2` selects y via explicit lexicographic Fq2 comparison (imaginary first,
//! then real). `AffineG2::get_ys_from_x_unchecked` in substrate-bn returns `(smaller_y, larger_y)`
//! sorted by the same ordering. This test empirically confirms they agree.

use bn as sb;
use bn::Group as SbGroup;
use parity_bn as pb;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn pb_g2_to_bytes(p: pb::AffineG2) -> [u8; 128] {
    let mut buf = [0u8; 128];
    p.x().imaginary().to_big_endian(&mut buf[..32]).expect("Fq2::imaginary");
    p.x().real().to_big_endian(&mut buf[32..64]).expect("Fq2::real");
    p.y().imaginary().to_big_endian(&mut buf[64..96]).expect("Fq2::imaginary");
    p.y().real().to_big_endian(&mut buf[96..128]).expect("Fq2::real");
    buf
}

fn sb_g2_to_bytes(p: sb::AffineG2) -> [u8; 128] {
    let mut buf = [0u8; 128];
    p.x().imaginary().to_big_endian(&mut buf[..32]).expect("Fq2::imaginary");
    p.x().real().to_big_endian(&mut buf[32..64]).expect("Fq2::real");
    p.y().imaginary().to_big_endian(&mut buf[64..96]).expect("Fq2::imaginary");
    p.y().real().to_big_endian(&mut buf[96..128]).expect("Fq2::real");
    buf
}

// ---------------------------------------------------------------------------
// Fq helpers
// ---------------------------------------------------------------------------

fn pb_fq_zero() -> pb::Fq {
    pb::Fq::from_u256(pb::arith::U256::from(0u64)).expect("0 < p")
}

fn pb_fq_one() -> pb::Fq {
    pb::Fq::from_u256(pb::arith::U256::from(1u64)).expect("1 < p")
}

// ---------------------------------------------------------------------------
// Fq2 square root — mirrors the algorithm in parse_compressed_g2 (converter.rs)
// which calls ckb-alt-bn128's Fq2::sqrt(). Implemented here using parity-bn
// 0.4.4's Fq2::pow(U256), following substrate-bn's cpu_sqrt algorithm.
// ---------------------------------------------------------------------------

fn pb_fq2_sqrt(a: pb::Fq2) -> Option<pb::Fq2> {
    let fq_minus3_div4 = pb::arith::U256::from([
        0x4f082305b61f3f51u64,
        0x65e05aa45a1c72a3u64,
        0x6e14116da0605617u64,
        0x0c19139cb84c680au64,
    ]);
    let fq_modulus = pb::arith::U256::from([
        0x3c208c16d87cfd47u64,
        0x97816a916871ca8du64,
        0xb85045b68181585du64,
        0x30644e72e131a029u64,
    ]);
    let fq_minus1_div2 = pb::arith::U256::from([
        0x9e10460b6c3e7ea3u64,
        0xcbc0b548b438e546u64,
        0xdc2822db40c0ac2eu64,
        0x183227397098d014u64,
    ]);

    let a1 = a.pow(fq_minus3_div4);
    let a1a = a1 * a;
    let alpha = a1 * a1a;
    let a0 = alpha.pow(fq_modulus) * alpha;

    let fq2_one = pb::Fq2::new(pb_fq_one(), pb_fq_zero());
    let neg_fq2_one = -fq2_one;

    if a0 == neg_fq2_one {
        return None;
    }

    if alpha == neg_fq2_one {
        let fq2_i = pb::Fq2::new(pb_fq_zero(), pb_fq_one());
        Some(fq2_i * a1a)
    } else {
        let b = (alpha + fq2_one).pow(fq_minus1_div2);
        Some(b * a1a)
    }
}

// ---------------------------------------------------------------------------
// Point generation
// ---------------------------------------------------------------------------

fn scalar_bytes(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

fn g2_uncompressed(n: u64) -> [u8; 128] {
    let scalar = sb::Fr::from_slice(&scalar_bytes(n)).expect("u64 fits in Fr");
    let pt = sb::G2::one() * scalar;
    let aff =
        sb::AffineG2::from_jacobian(pt).expect("nonzero scalar * G2 generator is never identity");
    sb_g2_to_bytes(aff)
}

fn pb_parse_g2_uncompressed(buf: &[u8; 128]) -> pb::AffineG2 {
    let x = pb::Fq2::new(
        pb::Fq::from_slice(&buf[32..64]).expect("x_real"),
        pb::Fq::from_slice(&buf[..32]).expect("x_imag"),
    );
    let y = pb::Fq2::new(
        pb::Fq::from_slice(&buf[96..128]).expect("y_real"),
        pb::Fq::from_slice(&buf[64..96]).expect("y_imag"),
    );
    pb::AffineG2::new(x, y).expect("point is on curve")
}

// ---------------------------------------------------------------------------
// Compressed G2 parsing replicas (mirrors converter.rs:76-140)
// ---------------------------------------------------------------------------

const MASK: u8 = 0xC0;
const COMPRESSED_NEGATIVE: u8 = 0xC0;
const COMPRESSED_POSITIVE: u8 = 0x80;

fn pb_compress_g2(p: pb::AffineG2) -> [u8; 64] {
    let mut buf = [0u8; 64];
    p.x().imaginary().to_big_endian(&mut buf[..32]).expect("Fq2");
    p.x().real().to_big_endian(&mut buf[32..64]).expect("Fq2");

    let y = p.y();
    let neg_y = -y;
    let yi = y.imaginary().into_u256();
    let nyi = neg_y.imaginary().into_u256();
    let y_gt_neg_y =
        if yi != nyi { yi > nyi } else { y.real().into_u256() > neg_y.real().into_u256() };

    if y_gt_neg_y {
        buf[0] |= COMPRESSED_NEGATIVE;
    } else {
        buf[0] = (buf[0] & !MASK) | COMPRESSED_POSITIVE;
    }
    buf
}

/// Replica of `parse_compressed_g2` (converter.rs:76-140).
fn pb_parse_compressed_g2(buf: &[u8; 64]) -> Result<pb::AffineG2, &'static str> {
    let m_data = buf[0] & MASK;
    if m_data == 0 || m_data == 0x40 {
        return Err("invalid flag");
    }

    let mut xi_bytes = [0u8; 32];
    xi_bytes.copy_from_slice(&buf[..32]);
    xi_bytes[0] &= !MASK;

    let x_imag = pb::Fq::from_slice(&xi_bytes).map_err(|_| "invalid x_imag")?;
    let x_real = pb::Fq::from_slice(&buf[32..64]).map_err(|_| "invalid x_real")?;
    let x = pb::Fq2::new(x_real, x_imag);

    let y_sq = x * x * x + pb::G2::b();
    let y = pb_fq2_sqrt(y_sq).ok_or("no G2 sqrt")?;
    let neg_y = -y;

    let yi = y.imaginary().into_u256();
    let nyi = neg_y.imaginary().into_u256();
    let y_gt_neg_y =
        if yi != nyi { yi > nyi } else { y.real().into_u256() > neg_y.real().into_u256() };

    let final_y = if m_data == COMPRESSED_NEGATIVE {
        if y_gt_neg_y {
            y
        } else {
            neg_y
        }
    } else {
        if y_gt_neg_y {
            neg_y
        } else {
            y
        }
    };

    pb::AffineG2::new(x, final_y).map_err(|_| "invalid G2 point")
}

/// Replica of the original `unchecked_compressed_x_to_g2_point` using substrate-bn.
fn sb_parse_compressed_g2(buf: &[u8; 64]) -> Result<sb::AffineG2, &'static str> {
    let m_data = buf[0] & MASK;
    if m_data == 0 || m_data == 0x40 {
        return Err("invalid flag");
    }

    let mut xi_bytes = [0u8; 32];
    xi_bytes.copy_from_slice(&buf[..32]);
    xi_bytes[0] &= !MASK;

    let x_imag = sb::Fq::from_slice(&xi_bytes).map_err(|_| "invalid x_imag")?;
    let x_real = sb::Fq::from_slice(&buf[32..64]).map_err(|_| "invalid x_real")?;
    let x = sb::Fq2::new(x_real, x_imag);

    let (smaller_y, larger_y) = sb::AffineG2::get_ys_from_x_unchecked(x).ok_or("no G2 sqrt")?;
    let final_y = if m_data == COMPRESSED_NEGATIVE { larger_y } else { smaller_y };
    sb::AffineG2::new(x, final_y).map_err(|_| "invalid G2 point")
}

// ---------------------------------------------------------------------------
// Tests: parse_compressed_g2 (converter.rs:76-140)
//
// Called twice in load_plonk_verifying_key_from_bytes for the two G2 points
// of the KZG verifying key (g2_0 and g2_1), which are the only G2 points in
// the entire verification. A wrong y-coordinate sign here means the final
// pairing check always fails.
// ---------------------------------------------------------------------------

proptest! {
    /// Both parsers return the same G2 point for compressed bytes generated via parity-bn.
    /// Verifies that the explicit lexicographic Fq2 comparison in `parse_compressed_g2`
    /// agrees with substrate-bn's `AffineG2::get_ys_from_x_unchecked` ordering.
    #[test]
    fn parse_compressed_g2_equiv(n in 1u64..u64::MAX) {
        let uncompressed = g2_uncompressed(n);
        let pt = pb_parse_g2_uncompressed(&uncompressed);
        let compressed = pb_compress_g2(pt);

        let pb_result = pb_parse_compressed_g2(&compressed);
        let sb_result = sb_parse_compressed_g2(&compressed);

        match (pb_result, sb_result) {
            (Ok(pb_pt), Ok(sb_pt)) => {
                prop_assert_eq!(
                    pb_g2_to_bytes(pb_pt),
                    sb_g2_to_bytes(sb_pt),
                    "G2 parsers disagree for scalar {}",
                    n
                );
            }
            (Err(e), Ok(_)) => prop_assert!(false, "parity-bn parse failed: {e}"),
            (Ok(_), Err(e)) => prop_assert!(false, "substrate-bn parse failed: {e}"),
            (Err(_), Err(_)) => {}
        }
    }
}
