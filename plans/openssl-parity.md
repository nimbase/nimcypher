# OpenSSL parity plan: why JIT bulk is 7-12x behind and how to close it.
#
# Status 2026-11-06: AES-128-GCM 242 vs 2860 MB/s, AES-256-GCM 232 vs 3000,
# ChaCha20-Poly1305 382 vs 2040. Kernels are fast in isolation, bulk path
# does not use them the way OpenSSL does.

## Where time goes (hypotheses for phase A to confirm)

1. AES-CTR is single-block. `gcm.nim gctrInto` calls `encryptBlockRaw`
   once per 16 B. The 8-block `AESENC` JIT batches in `aes_jit` exist but
   the GCM hot path never calls them. Cost: one Nim call + keystream xor
   loop per block, no AES pipelining.
2. GHASH is single-block serial. `absorb` calls `ghashFoldJit` once per
   16 B: one PCLMULQDQ dependency chain + one indirect call per block.
   No H^2..H^8 precompute, no 4x/8x aggregation, so PCLMUL latency is
   fully exposed.
3. Two passes over the data. `gcmEncryptUpdate` runs CTR over 16 KiB,
   then `absorb` runs GHASH over the ciphertext. OpenSSL does one fused
   pass with AES and GHASH interleaved, hiding both latencies and halving
   memory traffic.
4. ChaCha loop overhead. The 8-lane kernel does 89 ns/128 B vs 178 ns for
   2x 4-lane (2x per byte), but `chacha20DjbJitAvx2` still does per-word
   loads/xor/stores in Nim around it. Poly1305 (`polyBlocks`) is scalar
   32-bit with a serial dependency, so ChaCha+Poly stays Poly-bound.

## What OpenSSL does

- AES-CTR 6-8x interleaved AESENC, counters bumped in registers.
- GHASH 4-8x aggregated with precomputed H powers, one reduction per group.
- One loop: AES batch -> xor -> GHASH aggregate, data stays in regs/cache.
- ChaCha AVX2 4-8x plus vector Poly1305, fused add/xor/store.
- Zero alloc in steady state, schedule expanded once.

## Plan

- A (measure): bench AES batch vs single-block, GHASH fold alone, GCM
  one-shot, ChaCha DJB scalar vs JIT, Poly1305 alone, all on 16 KiB.
  Decides the CTR vs GHASH split before writing kernels.
- B (AES-GCM fused fast path, biggest win): `ctr8Jit` with in-reg counter
  increment, `ghashAgg8Jit` with H powers precomputed in `initGcm`,
  combined 8-block encrypt+xor+fold loop, one-block fallback for tails.
  Target 1.5-2.5 GB/s.
- C (ChaCha-Poly fast path): fused rounds+add+xor+store for 2 then 4
  blocks, vectorized Poly1305. Needed to move 382 MB/s toward 2 GB/s.
- D (system): hoist feature checks out of per-block path, avoid per-update
  allocs and tail-copy replication, reuse contexts and H powers.

## Gates

- Differential tests vs scalar for every new kernel, KATs for GCM/ChaCha.
- Host-verified encodings only (no VEX shufd-mem, no VEX shufb-mem, no
  MULX on the bad host class; functional smoke tests gate AVX2).
- Bench rule: Nim-level timing, `-d:ssl --threads:on --mm:arc -d:danger
  --opt:speed`, no `--release`, no CLI in timing path.

## Phase A results (2026-11-06, 16 KiB, JIT build, cpuTime)

| component | MB/s | note |
|---|---|---|
| AES-128 `encryptBlocks` batch ECB | 11787 | kernel ceiling, 8-block JIT |
| AES-128 `encryptBlockRaw` single loop | 352 | what `gctrInto`/`aesCtrUpdate` do today, 33x slower |
| GHASH JIT fold loop | 1646 | single-fold loop, serial |
| GHASH scalar fold loop | 343 | reference |
| `gcmLock` 16 KiB one-shot | 251 | matches bench_tls bulk, slower than either part alone |
| ChaCha `djbScalar` 16 KiB | 572 | raw stream, no Poly |
| ChaCha `djb` dispatched JIT | 678 | 8-lane DJB path, still Nim-loop bound |
| Poly1305 `update` 16 KiB | 1976 | scalar Poly alone is fast |

Math: 16 KiB = 1024 blocks. Batch AES takes ~1.4 us, GHASH ~10 us,
sum ~11 us = ~1.4 GB/s ceiling with current kernels. Single-block CTR
alone costs ~46 us, plus GHASH 10 us, plus two passes and per-block
calls = ~65 us = 251 MB/s observed. Conclusion: the gap is the path,
not the kernels. Using `encryptBlocks` for CTR closes ~45 us before
any new crypto is written. Same story on ChaCha: DJB 678 + Poly 1976
alone, 382 combined, so framing and sequential passes dominate.

Next: phase B, batched CTR in `gctrInto` as the first patch, then
fused 8-block encrypt+xor+fold.

## Phase B results (2026-11-06)

- Batched `gctrInto`: generate up to 32 counter blocks with `inc32`,
  one `encryptBlocks` call, flat xor. `gcmLock` 16 KiB micro went
  251 -> 861 MB/s (3.4x). Streaming/chunked differential vs one-shot,
  vs scalar, and 1-byte-chunked all pass in JIT and scalar builds.
- Fused whole-block loop (`fuseEncryptBlocks`/`fuseDecryptBlocks`,
  clean state only, tails stay on the slow path): first version with
  per-block xor+fold measured *slower* (673 vs 861, stable across
  runs) because the per-block xor defeated C-backend vectorization.
  Split into flat xor + fold loop over the same L1-resident 512 B
  chunk: 885-890 MB/s. `gcmUnlock`/`gcmUnlockScalar` now reuse
  `gcmDecryptUpdate` instead of duplicating absorb+decrypt.
- Remaining bulk cost is GHASH serial folds (~10 us of ~18 us):
  next is aggregated GHASH with precomputed H powers.
- Aggregated GHASH done: `assembleGhashAgg8` in `ghash_jit` folds 8
  blocks with one reduction (9 Karatsuba pairs: acc*P8, X1*P8 ..
  X8*P1, accumulated unreduced since shift+reduce are XOR-linear,
  single tail lifted from the fold kernel by register substitution).
  Powers P1..P8 precomputed in `initGcm` via dispatched folds;
  `foldBlocks` uses agg8 for groups of 8, serial tail otherwise, and
  backs `absorb` plus both fused loops. Alias re-declaration per
  dynasm block required inside the codegen loop (as in `aes_jit`).
  Micro `gcmLock` 16 KiB 887 -> 1411-1431 MB/s (+59%). Permanent
  `agg8 equals serial folds` differential in `tghash_jit` (60 random
  + zero/0xFF edges). Scalar path unchanged (115 MB/s).
