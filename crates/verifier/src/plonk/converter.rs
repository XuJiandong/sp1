use crate::{
    constants::{
        COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, MASK, PLONK_CLAIMED_VALUES_COUNT,
        PLONK_CLAIMED_VALUES_OFFSET, PLONK_Z_SHIFTED_OPENING_H_OFFSET,
        PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET,
    },
    error::Error,
};
use alloc::vec::Vec;
use parity_bn as pb;
use parity_bn::{AffineG1, Fr, G2};

use super::{
    error::PlonkError,
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

// Original: used crate::converter::{unchecked_compressed_x_to_g1_point, ...}
// Now reimplemented directly using parity-bn.

/// Parses a gnark-format compressed G1 point (32 bytes) using parity-bn.
///
/// The gnark format encodes the sign flag in the top 2 bits of the first byte:
/// - `COMPRESSED_POSITIVE` (0x80) → use the smaller y coordinate
/// - `COMPRESSED_NEGATIVE` (0xC0) → use the larger y coordinate
fn parse_compressed_g1(buf: &[u8]) -> Result<AffineG1, PlonkError> {
    // Original: crate::converter::unchecked_compressed_x_to_g1_point(buf).map_err(PlonkError::GeneralError)
    if buf.len() != 32 {
        return Err(PlonkError::GeneralError(Error::InvalidXLength));
    }

    let m_data = buf[0] & MASK;
    if m_data == 0 || m_data == COMPRESSED_INFINITY {
        return Err(PlonkError::GeneralError(Error::InvalidPoint));
    }

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(buf);
    x_bytes[0] &= !MASK;

    let x = pb::Fq::from_slice(&x_bytes).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    let b = pb::G1::b();
    let y_squared = x * x * x + b;
    let y = y_squared.sqrt().ok_or(PlonkError::GeneralError(Error::InvalidPoint))?;
    let neg_y = -y;

    let y_u256 = y.into_u256();
    let neg_y_u256 = neg_y.into_u256();

    // COMPRESSED_POSITIVE → smaller y; COMPRESSED_NEGATIVE → larger y
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

    pb::AffineG1::new(x, final_y).map_err(|_| PlonkError::GeneralError(Error::InvalidPoint))
}

/// Parses a gnark-format compressed G2 point (64 bytes) using parity-bn.
///
/// Layout: `[x_imag_32 (with flag) | x_real_32]`
/// - `COMPRESSED_POSITIVE` (0x80) → use the smaller y (by Fq2 lexicographic order)
/// - `COMPRESSED_NEGATIVE` (0xC0) → use the larger y
fn parse_compressed_g2(buf: &[u8]) -> Result<pb::AffineG2, PlonkError> {
    // Original: crate::converter::unchecked_compressed_x_to_g2_point(buf).map_err(PlonkError::GeneralError)
    if buf.len() != 64 {
        return Err(PlonkError::GeneralError(Error::InvalidXLength));
    }

    let m_data = buf[0] & MASK;

    if m_data == COMPRESSED_INFINITY {
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            // Point at infinity: return G2::zero() converted to affine
            // (This case shouldn't occur in valid PLONK proofs.)
            return Err(PlonkError::GeneralError(Error::InvalidPoint));
        }
        return Err(PlonkError::GeneralError(Error::InvalidPoint));
    }

    if m_data == 0 {
        return Err(PlonkError::GeneralError(Error::InvalidPoint));
    }

    let mut xi_bytes = [0u8; 32];
    xi_bytes.copy_from_slice(&buf[..32]);
    xi_bytes[0] &= !MASK;

    let x_imag =
        pb::Fq::from_slice(&xi_bytes).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let x_real =
        pb::Fq::from_slice(&buf[32..64]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    let x = pb::Fq2::new(x_real, x_imag);

    let b = pb::G2::b();
    let y_squared = x * x * x + b;
    let y = y_squared.sqrt().ok_or(PlonkError::GeneralError(Error::InvalidPoint))?;
    let neg_y = -y;

    // Fq2 comparison: imaginary part first, then real (matches substrate-bn Fq2::Ord)
    let y_gt_neg_y = {
        let yi = y.imaginary().into_u256();
        let nyi = neg_y.imaginary().into_u256();
        if yi != nyi {
            yi > nyi
        } else {
            y.real().into_u256() > neg_y.real().into_u256()
        }
    };

    // COMPRESSED_POSITIVE → smaller y; COMPRESSED_NEGATIVE → larger y
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

    pb::AffineG2::new(x, final_y).map_err(|_| PlonkError::GeneralError(Error::InvalidPoint))
}

/// Parses an uncompressed G1 point (64 bytes: x_32 || y_32) using parity-bn.
fn parse_uncompressed_g1(buf: &[u8]) -> Result<AffineG1, PlonkError> {
    // Original: crate::converter::uncompressed_bytes_to_g1_point(buf).map_err(PlonkError::GeneralError)
    if buf.len() != 64 {
        return Err(PlonkError::GeneralError(Error::InvalidXLength));
    }

    let x =
        pb::Fq::from_slice(&buf[..32]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let y =
        pb::Fq::from_slice(&buf[32..64]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    pb::AffineG1::new(x, y).map_err(|_| PlonkError::GeneralError(Error::InvalidPoint))
}

pub(crate) fn load_plonk_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<PlonkVerifyingKey, PlonkError> {
    // Verifying key for SP1 proofs have this size.
    if buffer.len() != 34368 {
        return Err(PlonkError::InvalidVerifyingKey);
    }

    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    let size_inv =
        Fr::from_slice(&buffer[8..40]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let generator =
        Fr::from_slice(&buffer[40..72]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;

    let coset_shift =
        Fr::from_slice(&buffer[80..112]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[112..144])?
    let s0 = parse_compressed_g1(&buffer[112..144])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[144..176])?
    let s1 = parse_compressed_g1(&buffer[144..176])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[176..208])?
    let s2 = parse_compressed_g1(&buffer[176..208])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[208..240])?
    let ql = parse_compressed_g1(&buffer[208..240])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[240..272])?
    let qr = parse_compressed_g1(&buffer[240..272])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[272..304])?
    let qm = parse_compressed_g1(&buffer[272..304])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[304..336])?
    let qo = parse_compressed_g1(&buffer[304..336])?;
    // Original: unchecked_compressed_x_to_g1_point(&buffer[336..368])?
    let qk = parse_compressed_g1(&buffer[336..368])?;
    let num_qcp = u32::from_be_bytes([buffer[368], buffer[369], buffer[370], buffer[371]]);

    // Verifying key for SP1 proofs have this size.
    if num_qcp != 1 {
        return Err(PlonkError::InvalidVerifyingKey);
    }

    let mut qcp = Vec::new();
    let mut offset = 372;

    for _ in 0..num_qcp {
        // Original: unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?
        let point = parse_compressed_g1(&buffer[offset..offset + 32])?;
        qcp.push(point);
        offset += 32;
    }

    // Original: unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?
    let g1 = parse_compressed_g1(&buffer[offset..offset + 32])?;
    // Original: unchecked_compressed_x_to_g2_point(&buffer[offset + 32..offset + 96])?
    let g2_0 = parse_compressed_g2(&buffer[offset + 32..offset + 96])?;
    // Original: unchecked_compressed_x_to_g2_point(&buffer[offset + 96..offset + 160])?
    let g2_1 = parse_compressed_g2(&buffer[offset + 96..offset + 160])?;

    offset += 160 + 33792;

    let num_commitment_constraint_indexes = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]) as usize;

    // Verifying key for SP1 proofs have this size.
    if num_commitment_constraint_indexes != 1 {
        return Err(PlonkError::InvalidVerifyingKey);
    }

    let mut commitment_constraint_indexes = Vec::new();
    offset += 4;
    for _ in 0..num_commitment_constraint_indexes {
        let index = u64::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]) as usize;
        commitment_constraint_indexes.push(index);
        offset += 8;
    }

    let result = PlonkVerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::KZGVerifyingKey {
            g2: [G2::from(g2_0), G2::from(g2_1)],
            g1: g1.into(),
            lines: [[[LineEvaluationAff {
                r0: E2 { a0: Fr::zero(), a1: Fr::zero() },
                r1: E2 { a0: Fr::zero(), a1: Fr::zero() },
            }; 66]; 2]; 2],
        },
        coset_shift,
        s: [s0, s1, s2],
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    };

    Ok(result)
}

/// See https://github.com/jtguibas/gnark/blob/26e3df73fc223292be8b7fc0b7451caa4059a649/backend/plonk/bn254/solidity.go
/// for how the proof is serialized.
pub(crate) fn load_plonk_proof_from_bytes(
    buffer: &[u8],
    num_bsb22_commitments: usize,
) -> Result<PlonkProof, PlonkError> {
    // Verifying key for SP1 proofs have this size.
    if num_bsb22_commitments != 1 {
        return Err(PlonkError::InvalidVerifyingKey);
    }

    if buffer.len()
        != PLONK_CLAIMED_VALUES_OFFSET
            + PLONK_CLAIMED_VALUES_COUNT * 32
            + PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET
            + PLONK_Z_SHIFTED_OPENING_H_OFFSET
            + num_bsb22_commitments * 32
            + num_bsb22_commitments * 64
    {
        return Err(PlonkError::GeneralError(Error::InvalidData));
    }

    // Original: uncompressed_bytes_to_g1_point(&buffer[..64])?
    let lro0 = parse_uncompressed_g1(&buffer[..64])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[64..128])?
    let lro1 = parse_uncompressed_g1(&buffer[64..128])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[128..192])?
    let lro2 = parse_uncompressed_g1(&buffer[128..192])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[192..256])?
    let h0 = parse_uncompressed_g1(&buffer[192..256])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[256..320])?
    let h1 = parse_uncompressed_g1(&buffer[256..320])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[320..384])?
    let h2 = parse_uncompressed_g1(&buffer[320..384])?;

    // Stores l_at_zeta, r_at_zeta, o_at_zeta, s 1_at_zeta, s2_at_zeta, bsb22_commitments
    let mut claimed_values = Vec::with_capacity(PLONK_CLAIMED_VALUES_COUNT + num_bsb22_commitments);
    let mut offset = PLONK_CLAIMED_VALUES_OFFSET;
    for _ in 0..PLONK_CLAIMED_VALUES_COUNT {
        let value = Fr::from_slice(&buffer[offset..offset + 32])
            .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
        claimed_values.push(value);
        offset += 32;
    }

    // Original: uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?
    let z = parse_uncompressed_g1(&buffer[offset..offset + 64])?;
    let z_shifted_opening_value = Fr::from_slice(&buffer[offset + 64..offset + 96])
        .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    offset += PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET;

    // Original: uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?
    let batched_proof_h = parse_uncompressed_g1(&buffer[offset..offset + 64])?;
    // Original: uncompressed_bytes_to_g1_point(&buffer[offset + 64..offset + 128])?
    let z_shifted_opening_h = parse_uncompressed_g1(&buffer[offset + 64..offset + 128])?;
    offset += PLONK_Z_SHIFTED_OPENING_H_OFFSET;

    for _ in 0..num_bsb22_commitments {
        let commitment = Fr::from_slice(&buffer[offset..offset + 32])
            .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
        claimed_values.push(commitment);
        offset += 32;
    }

    let mut bsb22_commitments = Vec::with_capacity(num_bsb22_commitments);
    for _ in 0..num_bsb22_commitments {
        // Original: uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?
        let commitment = parse_uncompressed_g1(&buffer[offset..offset + 64])?;
        bsb22_commitments.push(commitment);
        offset += 64;
    }

    let result = PlonkProof {
        lro: [lro0, lro1, lro2],
        z,
        h: [h0, h1, h2],
        bsb22_commitments,
        batched_proof: BatchOpeningProof { h: batched_proof_h, claimed_values },
        z_shifted_opening: OpeningProof {
            h: z_shifted_opening_h,
            claimed_value: z_shifted_opening_value,
        },
    };

    Ok(result)
}

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<Vec<u8>, PlonkError> {
    // Original: unsafe { transmute } then reverse each 32-byte half.
    // (That worked for substrate-bn's standard form; parity-bn uses Montgomery form
    // internally, so we must use to_big_endian for canonical serialization.)
    let mut bytes = [0u8; 64];
    g1.x()
        .to_big_endian(&mut bytes[..32])
        .map_err(|_| PlonkError::GeneralError(Error::InvalidPoint))?;
    g1.y()
        .to_big_endian(&mut bytes[32..])
        .map_err(|_| PlonkError::GeneralError(Error::InvalidPoint))?;
    Ok(bytes.to_vec())
}
