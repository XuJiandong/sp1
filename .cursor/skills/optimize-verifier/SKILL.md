---
name: optimize-verifier
description: Optimize crate verifier by replacing substrate-bn with parity-bn.
---

# Optimize Crate Verifier

Optimize the verifier crate (under `crates/verifier`). The original code uses `substrate-bn`; the goal is to replace it with `parity-bn`. Further instructions will be provided by the user.

## Context

Before reading source code, check the summary at:

`~/projects/2-versions-bn/differential-testing/report.md`

This is **very important**. If it is insufficient, refer to the source code directly:

- parity-bn: `~/projects/2-versions-bn/parity-bn`
- substrate-bn: `~/projects/2-versions-bn/substrate-bn`

Cargo dependencies:

```toml
parity-bn = { version = "0.1.3", package = "ckb-alt-bn128" }
bn = { version = "=0.6.0", package = "substrate-bn-succinct-rs" }
```

## Requirements

- Only modify `verify_gnark_proof` and its nested functions.
- Keep the original code as comments after each change to make it easy to review.
- Place utility functions (e.g., conversions between `parity-bn` and `substrate-bn` types) in `src/plonk/utility.rs`.

## How to Build

```bash
cd crates/verifier
CLANG=clang-19 cargo build --target=riscv64imac-unknown-none-elf --no-default-features
```
Don't try to run original unit tests: It can't pass(no problem).
