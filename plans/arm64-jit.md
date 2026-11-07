# ARM64 JIT status

Date: 2026-11-07. No ARM hardware in-house; all ARM work is built on
x64 and proven by `clue check --cpu:arm64`, clang cross-goldens,
`otool`-disassembly of assembled kernels, and execution
differentials on the ARM CI runners (macos-15, ubuntu-24.04-arm).

## Supported today

| path | amd64 | arm64 |
|---|---|---|
| scalar (all algos) | yes | yes |
| nimsimd AES / ChaCha20 / Blake2b | yes | yes |
| nimsimd GHASH | yes | no (amd64-only) |
| JIT AES enc/dec/ctr batch-8 | yes | yes (2026-11-07) |
| JIT GHASH / fused GCM | yes | no |
| JIT ChaCha / Blake2b / MULX | yes | no |
| JIT cpu detector | yes | no |

On arm64 with `-d:features.nimcypher.nimdynasm`, bulk AES-GCM runs
JIT AES (`encryptBlocks` dispatch + `ctrCrypt8Jit` fuse sites) with
scalar GHASH. All other JIT call sites stay amd64-gated; the four
non-AES `*_jit` suites skip on ARM.

## AES backend notes (`internal/aes_jit`)

- States v0-v7, round key v31, ctr scratch v30; AAPCS64 arg order
  (enc: nrk/dst/src; dec: +nrkInv; ctr: +ctrp). Only caller-saved
  regs, 16-aligned 128 B stack area, `ret`-terminated leaf.
- dynasm has no crypto mnemonics, so aese/aesd/aesmc/aesimc plus
  dynamic-index ldr/str-Q and eor emit raw words via `arm*Word`
  helpers (bases in `aes_jit`, always compiled). Static-reg key
  loads, integer, stack and branch ops use `arch aarch64` DSL.
- Pinned by `taes_jit` "arm64 crypto word goldens" (17 clang-checked
  words, run on every host) and by full-kernel otool disassembly
  (sequence, offsets, ABI, op counts exact).
- Round/decrypt order mirrors `aes_simd` encBatch4/decBatch4
  (AESE folds AddRoundKey; AESD+AESIMC equivalent inverse cipher).
- Gotcha: Nim locals named like scalar FP regs (`d1`) are parsed as
  registers by the DSL — use non-colliding names (`km1`).

## Remaining work (in order)

1. GHASH JIT — needs `PMULL` in dynasm (aarch64 backend has no
   crypto/poly insns). Highest value: remaining bulk-GCM bottleneck
   on ARM, unblocks the fused GCM kernel there.
2. ChaCha JIT — NEON integer vector ops mostly exist; check
   rotate (`shl`/`sri`) coverage in dynasm first.
3. Blake2b JIT — needs 64-bit vector rotates; dynasm encoder work
   first (no vector shifts today).
4. MULX equivalent — ARM `UMULH` is scalar and trivial; small.
5. cpu detector — `getauxval(AT_HWCAP)` on Linux, always-true on
   macOS; gates crypto kernels at runtime.

## Execution proof (2026-11-07)

- `nimble test_jit` (new nimble task) runs the five `*_jit` suites
  plus `tgcm_fused`/`taes`/`tgcm` with nimdynasm; the `test-jit` CI
  job runs it natively on all four runners.
- Requires dynasm >= 0.2.0 in the registry: the 0.1.0 release has no
  x64 assemblers at all, so the job fails at dependency resolution
  until 0.2.0 is published. Publish order: dynasm 0.2.0 first, then
  merge the nimcypher side.
- The macOS step pins `-arch arm64` codegen (same workaround as the
  reusable test workflow) so kernels execute natively on Apple
  Silicon runners.

## Gates (same as x86)

- Differential vs scalar for every kernel, host-verified encodings
  only, no execution-gated paths without a functional probe.
- `*_jit` suites require the nimdynasm flag AND their arch, else
  skip (plain `nimble test` compiles everything with no flags).
