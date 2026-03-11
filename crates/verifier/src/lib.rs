//! This crate provides verifiers for SP1 Groth16 and Plonk BN254 proofs in a no-std environment.
//! It is patched for efficient verification within the SP1 zkVM context.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

pub static PLONK_VK_BYTES: &[u8] = include_bytes!("../vk-artifacts/plonk_vk.bin");
pub static GROTH16_VK_BYTES: &[u8] = include_bytes!("../vk-artifacts/groth16_vk.bin");

/// Precomputed VK merkle tree root as 32 bytes (big-endian bn254 representation).
/// Derived from the recursion verifying key data at build time.
pub static VK_ROOT_BYTES: &[u8] = &[
    0x00, 0x8c, 0xd5, 0x6e, 0x10, 0xc2, 0xfe, 0x24, 0x79, 0x5c, 0xff, 0x1e, 0x1d, 0x1f, 0x40, 0xd3,
    0xa3, 0x24, 0x52, 0x8d, 0x31, 0x56, 0x74, 0xda, 0x45, 0xd2, 0x6a, 0xfb, 0x37, 0x6e, 0x86, 0x70,
];

#[cfg(feature = "std")]
mod recursion_vks;
#[cfg(feature = "std")]
pub use recursion_vks::VerifierRecursionVks;

#[cfg(feature = "std")]
pub mod compressed;

mod constants;
pub mod converter;
mod error;

#[cfg(feature = "std")]
mod proof;
#[cfg(feature = "std")]
pub use proof::*;

mod utils;
pub use utils::*;

pub use groth16::{error::Groth16Error, Groth16Verifier};
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::{error::PlonkError, PlonkVerifier};
mod plonk;

#[cfg(all(test, feature = "std"))]
mod tests;

#[cfg(all(test, feature = "std"))]
#[test]
fn vk_root_bytes_not_stale() {
    use slop_algebra::PrimeField;
    use sp1_hypercube::koalabears_to_bn254;
    let vks = recursion_vks::VerifierRecursionVks::default();
    let bn254 = koalabears_to_bn254(&vks.root());
    let bigint = bn254.as_canonical_biguint();
    let be_bytes = bigint.to_bytes_be();
    let mut expected = [0u8; 32];
    let start = 32 - be_bytes.len();
    expected[start..].copy_from_slice(&be_bytes);
    assert_eq!(VK_ROOT_BYTES, expected, "VK_ROOT_BYTES is stale — regenerate it");
}
