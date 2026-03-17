use crate::error::Error;
use bn as sb;
use parity_bn as pb;

use super::error::PlonkError;

pub(crate) fn map_pb_field_err(e: pb::FieldError) -> sb::FieldError {
    match e {
        pb::FieldError::InvalidSliceLength => sb::FieldError::InvalidSliceLength,
        pb::FieldError::InvalidU512Encoding => sb::FieldError::InvalidU512Encoding,
        pb::FieldError::NotMember => sb::FieldError::NotMember,
    }
}

#[allow(dead_code)]
pub(crate) fn pb_fq_to_sb(fq: pb::Fq) -> Result<sb::Fq, PlonkError> {
    let mut buf = [0u8; 32];
    fq.to_big_endian(&mut buf).expect("32-byte buffer always succeeds");
    sb::Fq::from_slice(&buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))
}

#[allow(dead_code)]
pub(crate) fn pb_fr_to_sb(fr: pb::Fr) -> Result<sb::Fr, PlonkError> {
    // NOTE: pb::Fr::to_big_endian serializes raw Montgomery limbs; use into_u256() for canonical bytes.
    let u256 = fr.into_u256();
    let mut buf = [0u8; 32];
    u256.to_big_endian(&mut buf).expect("32-byte buffer always succeeds");
    sb::Fr::from_slice(&buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))
}

pub(crate) fn pb_affine_g1_to_sb(g1: pb::AffineG1) -> Result<sb::AffineG1, PlonkError> {
    let mut x_buf = [0u8; 32];
    let mut y_buf = [0u8; 32];
    g1.x().to_big_endian(&mut x_buf).expect("32-byte buffer always succeeds");
    g1.y().to_big_endian(&mut y_buf).expect("32-byte buffer always succeeds");
    let x = sb::Fq::from_slice(&x_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let y = sb::Fq::from_slice(&y_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    Ok(sb::AffineG1::new_unchecked(x, y))
}

pub(crate) fn pb_affine_g2_to_sb(g2: pb::AffineG2) -> Result<sb::AffineG2, PlonkError> {
    let mut xr_buf = [0u8; 32];
    let mut xi_buf = [0u8; 32];
    let mut yr_buf = [0u8; 32];
    let mut yi_buf = [0u8; 32];
    g2.x().real().to_big_endian(&mut xr_buf).expect("32-byte buffer always succeeds");
    g2.x().imaginary().to_big_endian(&mut xi_buf).expect("32-byte buffer always succeeds");
    g2.y().real().to_big_endian(&mut yr_buf).expect("32-byte buffer always succeeds");
    g2.y().imaginary().to_big_endian(&mut yi_buf).expect("32-byte buffer always succeeds");
    let x = sb::Fq2::new(
        sb::Fq::from_slice(&xr_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?,
        sb::Fq::from_slice(&xi_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?,
    );
    let y = sb::Fq2::new(
        sb::Fq::from_slice(&yr_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?,
        sb::Fq::from_slice(&yi_buf).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?,
    );
    Ok(sb::AffineG2::new_unchecked(x, y))
}
