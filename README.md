# Optimized SP1 Verifier for ckb-vm

An optimized port of the SP1 verifier (Plonk proof) targeting ckb-vm, based on SP1 6.0.2.

The original SP1 verifier lacks `no_std` support and has high cycle counts (~6000M cycles), making it unusable for on-chain scripts on ckb-vm. This fork addresses both limitations.

## Changes

Key modifications from the original:

1. Replaced the bn254 (alt\_bn128) elliptic curve implementation with the highly optimized [ckb-alt-bn128](https://crates.io/crates/ckb-alt-bn128)
2. Ported to `no_std` Rust
3. Only the Plonk verifier has been updated; Groth16 is not ported or optimized

As a result, cycle count for a single verification is reduced from ~1000M to ~63M, with a binary size of 246 KB — viable for on-chain use on ckb-vm.

## Usage

Add the dependency to your `Cargo.toml`:

```toml
sp1-verifier = { git = "https://github.com/XuJiandong/sp1.git", default-features = false, rev = "f5586e9" }
```

Example:

```rust
use sp1_verifier::PlonkVerifier;

pub fn main() -> Result<(), Error> {
    let vk_hash = "0x00e5c18e0c045a455db8eb2bee09cb2db3c87129e0972cc1562ce3c13d6c9c10";
    let proof = []; // fill proof here
    let public_values = []; // fill public values here
    PlonkVerifier::verify(&proof, &public_values, &vk_hash, sp1_verifier::PLONK_VK_BYTES)
        .expect("plonk verify failed");
}
```

For more usage examples, see the [official SP1 documentation](https://docs.succinct.xyz/docs/sp1/generating-proofs/off-chain-verification).

A full benchmark is available [here](https://github.com/XuJiandong/ckb-rust-algorithm-benchmarks/tree/master/contracts/sp1-test).

## Notes

The original SP1 README is [here](https://github.com/succinctlabs/sp1).
