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
pub(crate) fn affine_g1_msm(points: &[pb::AffineG1], scalars: &[pb::Fr]) -> pb::AffineG1 {
    let mut acc = pb::G1::zero();
    for (p, s) in points.iter().zip(scalars.iter()) {
        acc = acc + pb::G1::from(*p) * *s;
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
