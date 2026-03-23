use alloc::vec::Vec;
use parity_bn as pb;
use pb::arith::U256;
use pb::Group;

use crate::error::Error;

use super::error::PlonkError;

/// Converts a U256 to a big-endian [u8; 32] array.
pub(crate) fn u256_to_bytes_be(u: &U256) -> [u8; 32] {
    let mut buf = [0u8; 32];
    u.to_big_endian(&mut buf).expect("32-byte buffer always succeeds");
    buf
}

/// Parses bytes as a big-endian integer and reduces modulo the Fr modulus.
/// Accepts any length; pads with zeros on the left to 64 bytes if shorter.
pub(crate) fn fr_from_bytes_be_mod_order(bytes: &[u8]) -> pb::Fr {
    // Original: bn::Fr::from_bytes_be_mod_order(bytes)
    let mut buf = [0u8; 64];
    if bytes.len() >= 64 {
        buf.copy_from_slice(&bytes[bytes.len() - 64..]);
    } else {
        buf[64 - bytes.len()..].copy_from_slice(bytes);
    }
    pb::Fr::interpret(&buf)
}

/// Multi-scalar multiplication: computes sum_i(scalars[i] * points[i]).
/// Original: bn::AffineG1::msm(&points, &scalars)
///
/// # Algorithm: Straus (windowed Shamir)
///
/// Instead of computing each `scalar * point` independently (costly), we process
/// all scalars **in lockstep** using a shared double-and-add loop.
///
/// A 4-bit window means we look at each scalar 4 bits at a time (a nibble 0..15),
/// and use a precomputed table to turn each nibble into a single point addition.
pub(crate) fn affine_g1_msm(points: &[pb::AffineG1], scalars: &[pb::Fr]) -> pb::AffineG1 {
    let n = points.len().min(scalars.len());
    // Step 1: Serialize scalars to big-endian bytes
    let scalar_bytes: Vec<[u8; 32]> =
        scalars[..n].iter().map(|s| u256_to_bytes_be(&s.into_u256())).collect();

    // Step 2: Build lookup tables
    //
    // For each point P, precompute [0·P, 1·P, 2·P, …, 15·P].
    // This lets us replace up to 4 doublings + conditional adds with a single
    // table lookup per point per window.
    let tables: Vec<[pb::G1; 16]> = points[..n]
        .iter()
        .map(|p| {
            let g = pb::G1::from(*p);
            let mut t = [pb::G1::zero(); 16];
            t[1] = g;
            for j in 2..16 {
                t[j] = t[j - 1] + g;
            }
            t
        })
        .collect();

    // Step 3: Windowed evaluation (MSB → LSB)
    //
    // We split each 256-bit scalar into 64 windows of 4 bits.
    // In big-endian byte layout:
    //   byte 0:  [window 0 (high nibble)] [window 1 (low nibble)]
    //   byte 1:  [window 2 (high nibble)] [window 3 (low nibble)]
    //   ...
    //   byte 31: [window 62]              [window 63]
    let mut acc = pb::G1::zero();

    for window in 0..64u8 {
        // Double the accumulator 4 times (shift left by 4 bits).
        acc = acc + acc;
        acc = acc + acc;
        acc = acc + acc;
        acc = acc + acc;

        // Extract the 4-bit nibble for this window from each scalar,
        // then add the corresponding precomputed multiple.
        let byte = (window / 2) as usize;
        let shift = if window % 2 == 0 { 4 } else { 0 };

        for (table, s) in tables.iter().zip(scalar_bytes.iter()) {
            let nibble = (s[byte] >> shift) & 0xF;
            if nibble != 0 {
                acc = acc + table[nibble as usize];
            }
        }
    }

    pb::AffineG1::from_jacobian(acc)
        .expect("MSM result should not be point at infinity in valid proof")
}

/// Negates an AffineG1 point via G1 Jacobian arithmetic.
/// Original: -affine_g1 (substrate-bn had Neg for AffineG1)
pub(crate) fn affine_g1_neg(p: pb::AffineG1) -> pb::AffineG1 {
    pb::AffineG1::from_jacobian(-pb::G1::from(p))
        .expect("negation of affine point cannot produce point at infinity")
}

/// Adds two AffineG1 points via G1 Jacobian arithmetic.
/// Original: affine_g1_a + affine_g1_b (substrate-bn had Add for AffineG1)
pub(crate) fn affine_g1_add(a: pb::AffineG1, b: pb::AffineG1) -> Result<pb::AffineG1, PlonkError> {
    pb::AffineG1::from_jacobian(pb::G1::from(a) + pb::G1::from(b))
        .ok_or(PlonkError::GeneralError(Error::InvalidPoint))
}

/// Subtracts two AffineG1 points via G1 Jacobian arithmetic.
/// Original: affine_g1_a - affine_g1_b (substrate-bn had Sub for AffineG1)
pub(crate) fn affine_g1_sub(a: pb::AffineG1, b: pb::AffineG1) -> Result<pb::AffineG1, PlonkError> {
    pb::AffineG1::from_jacobian(pb::G1::from(a) - pb::G1::from(b))
        .ok_or(PlonkError::GeneralError(Error::InvalidPoint))
}
