//! Proptests comparing ckb-alt-bn128 (new) vs substrate-bn-succinct-rs (original) for G2 point parsing.
//!
//! Directly calls sp1-verifier's `converter::parse_compressed_g2` (converter.rs:76-140;
//! called 2× in load_plonk_verifying_key_from_bytes for g2_0 and g2_1 of the KZG key).
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
use sp1_verifier::plonk::converter::parse_compressed_g2;

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

fn sb_compress_g2(buf: &[u8; 128]) -> [u8; 64] {
    let x = sb::Fq2::new(
        sb::Fq::from_slice(&buf[32..64]).expect("x_real"),
        sb::Fq::from_slice(&buf[..32]).expect("x_imag"),
    );
    let y = sb::Fq2::new(
        sb::Fq::from_slice(&buf[96..128]).expect("y_real"),
        sb::Fq::from_slice(&buf[64..96]).expect("y_imag"),
    );
    let pt = sb::AffineG2::new(x, y).expect("point is on curve");
    let mut compressed = [0u8; 64];
    pt.x().imaginary().to_big_endian(&mut compressed[..32]).expect("Fq2");
    pt.x().real().to_big_endian(&mut compressed[32..64]).expect("Fq2");

    let y = pt.y();
    let neg_y = -y;
    let y_gt_neg_y = if y.imaginary() != neg_y.imaginary() {
        y.imaginary() > neg_y.imaginary()
    } else {
        y.real() > neg_y.real()
    };

    if y_gt_neg_y {
        compressed[0] |= 0xC0;
    } else {
        compressed[0] = (compressed[0] & 0x3F) | 0x80;
    }
    compressed
}

fn sb_parse_compressed_g2(buf: &[u8; 64]) -> Result<sb::AffineG2, &'static str> {
    const MASK: u8 = 0xC0;
    const COMPRESSED_NEGATIVE: u8 = 0xC0;

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

fn with_g2_flag(mut buf: [u8; 64], negative: bool) -> [u8; 64] {
    buf[0] &= 0x3F;
    buf[0] |= if negative { 0xC0 } else { 0x80 };
    buf
}

#[test]
fn parse_compressed_g2_rejects_bad_lengths_and_flags() {
    for len in [0usize, 1, 63, 65] {
        let buf = vec![0u8; len];
        assert!(parse_compressed_g2(&buf).is_err(), "len={len} should fail");
    }

    let mut no_flag = [0u8; 64];
    no_flag[0] = 0x00;
    assert!(parse_compressed_g2(&no_flag).is_err());

    let mut infinity = [0u8; 64];
    infinity[0] = 0x40;
    assert!(parse_compressed_g2(&infinity).is_err());
}

proptest! {
    #[test]
    fn parse_compressed_g2_equiv(n in 1u64..u64::MAX) {
        let uncompressed = g2_uncompressed(n);
        let compressed = sb_compress_g2(&uncompressed);

        let pb_result = parse_compressed_g2(&compressed);
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
            (Err(e), Ok(_)) => prop_assert!(false, "ckb-alt-bn128 parse failed: {e}"),
            (Ok(_), Err(e)) => prop_assert!(false, "substrate-bn parse failed: {e}"),
            (Err(_), Err(_)) => {}
        }
    }

    #[test]
    fn parse_compressed_g2_random_equiv(buf in any::<[u8; 64]>(), negative in any::<bool>()) {
        let compressed = with_g2_flag(buf, negative);

        let pb_result = parse_compressed_g2(&compressed);
        let sb_result = sb_parse_compressed_g2(&compressed);

        match (pb_result, sb_result) {
            (Ok(pb_pt), Ok(sb_pt)) => {
                prop_assert_eq!(pb_g2_to_bytes(pb_pt), sb_g2_to_bytes(sb_pt));
            }
            (Err(_), Err(_)) => {}
            (Err(e), Ok(_)) => prop_assert!(false, "ckb-alt-bn128 parse failed: {e}"),
            (Ok(_), Err(e)) => prop_assert!(false, "substrate-bn parse failed: {e}"),
        }
    }
}
