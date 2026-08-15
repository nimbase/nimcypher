# SIMD-accelerated ChaCha20 rounds.
#
# Two kernels:
#
# * `simdRounds`  — four-lane kernel processing one ChaCha20 block, for the
#   DJB one-shot's odd/partial blocks and for HChaCha20. SSE2 (amd64) and
#   NEON (arm64), both baseline on their platforms.
# * `simdRounds2` — eight-lane AVX2 kernel processing two blocks in
#   parallel (each 128-bit lane of the 256-bit register holds one block).
#   Used for the bulk of the DJB one-shot on amd64; requires `-mavx2`
#   (enabled by `chacha20.nim` when the feature is active).
#
# The four 32-bit words a quarter-round touches are processed in parallel in
# one SIMD register: the four column quarter-rounds of the "column round"
# collapse into a single vector quarter-round, and the diagonal round first
# rotates the lanes of three operand vectors so each diagonal group lines up
# in a column again, then rotates them back.
#
# Compiled only when `features.nimcypher.nimsimd` is defined; see
# `src/nimcypher/algos/chacha20.nim` and the nimcypher.nimble feature block.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when defined(amd64):
  import nimsimd/sse2
  import nimsimd/avx2

  # nimsimd does not vendor the plain unaligned 256-bit load/store.
  {.push header: "immintrin.h".}
  func mm256_loadu_si256(p: pointer): M256i {.importc: "_mm256_loadu_si256".}
  func mm256_storeu_si256(p: pointer, a: M256i) {.importc: "_mm256_storeu_si256".}
  {.pop.}

  # --- SSE2 kernel (one block, four lanes) ---
  template vadd(a, b: M128i): M128i = mm_add_epi32(a, b)
  template vxor(a, b: M128i): M128i = mm_xor_si128(a, b)
  template vrotl(a: M128i, n: int): M128i =
    mm_or_si128(mm_slli_epi32(a, int32(n)), mm_srli_epi32(a, int32(32 - n)))
  template vshuf(a: M128i, n: int): M128i =
    when n == 1:
      mm_shuffle_epi32(a, 0x39'i32)
    elif n == 2:
      mm_shuffle_epi32(a, 0x4e'i32)
    else:
      mm_shuffle_epi32(a, 0x93'i32)
  template vload(p: pointer): M128i = mm_loadu_si128(p)
  template vstore(p: pointer, v: M128i) = mm_storeu_si128(p, v)

  # --- AVX2 kernel (two blocks, eight lanes) ---
  template wadd(a, b: M256i): M256i = mm256_add_epi32(a, b)
  template wxor(a, b: M256i): M256i = mm256_xor_si256(a, b)
  template wrotl(a: M256i, n: int): M256i =
    mm256_or_si256(mm256_slli_epi32(a, int32(n)), mm256_srli_epi32(a, int32(32 - n)))
  template wshuf(a: M256i, n: int): M256i =
    when n == 1:
      mm256_shuffle_epi32(a, 0x39'i32)
    elif n == 2:
      mm256_shuffle_epi32(a, 0x4e'i32)
    else:
      mm256_shuffle_epi32(a, 0x93'i32)
  template wload(p: pointer): M256i = mm256_loadu_si256(p)
  template wstore(p: pointer, v: M256i) = mm256_storeu_si256(p, v)
elif defined(arm64):
  import nimsimd/neon

  template vadd(a, b: uint32x4): uint32x4 = vaddq_u32(a, b)
  template vxor(a, b: uint32x4): uint32x4 = veorq_u32(a, b)
  template vrotl(a: uint32x4, n: int): uint32x4 =
    vorrq_u32(vshlq_n_u32(a, n), vshrq_n_u32(a, 32 - n))
  template vshuf(a: uint32x4, n: int): uint32x4 =
    vextq_u32(a, a, n)
  template vload(p: pointer): uint32x4 = vld1q_u32(p)
  template vstore(p: pointer, v: uint32x4) = vst1q_u32(p, v)
else:
  {.error: "chacha20_simd requires amd64 (SSE2/AVX2) or arm64 (NEON).".}

template vQuarterRound(a, b, c, d: untyped) =
  a = vadd(a, b)
  d = vrotl(vxor(d, a), 16)
  c = vadd(c, d)
  b = vrotl(vxor(b, c), 12)
  a = vadd(a, b)
  d = vrotl(vxor(d, a), 8)
  c = vadd(c, d)
  b = vrotl(vxor(b, c), 7)

template wQuarterRound(a, b, c, d: untyped) =
  a = wadd(a, b)
  d = wrotl(wxor(d, a), 16)
  c = wadd(c, d)
  b = wrotl(wxor(b, c), 12)
  a = wadd(a, b)
  d = wrotl(wxor(d, a), 8)
  c = wadd(c, d)
  b = wrotl(wxor(b, c), 7)

proc simdRounds*(outp: var array[16, uint32], inp: array[16, uint32]) {.inline.} =
  ## Apply 20 rounds of ChaCha20 to one block (same contract as the scalar
  ## `chacha20RoundsScalar`).
  var a = vload(cast[pointer](unsafeAddr inp[0]))
  var b = vload(cast[pointer](unsafeAddr inp[4]))
  var c = vload(cast[pointer](unsafeAddr inp[8]))
  var d = vload(cast[pointer](unsafeAddr inp[12]))
  for _ in 0 ..< 10:
    vQuarterRound(a, b, c, d)
    b = vshuf(b, 1)
    c = vshuf(c, 2)
    d = vshuf(d, 3)
    vQuarterRound(a, b, c, d)
    b = vshuf(b, 3)
    c = vshuf(c, 2)
    d = vshuf(d, 1)
  vstore(cast[pointer](unsafeAddr outp[0]), a)
  vstore(cast[pointer](unsafeAddr outp[4]), b)
  vstore(cast[pointer](unsafeAddr outp[8]), c)
  vstore(cast[pointer](unsafeAddr outp[12]), d)

proc simdRounds2*(outp: var array[32, uint32], inp: array[32, uint32]) {.inline.} =
  ## Apply 20 rounds of ChaCha20 to two blocks at once (AVX2, amd64 only).
  ## `inp`/`outp` hold two interleaved blocks: word `w` of block 0 lives at
  ## index `(w shr 2) shl 3 + (w and 3)`, word `w` of block 1 at index
  ## `(w shr 2) shl 3 + (w and 3) + 4`.
  var a = wload(cast[pointer](unsafeAddr inp[0]))
  var b = wload(cast[pointer](unsafeAddr inp[8]))
  var c = wload(cast[pointer](unsafeAddr inp[16]))
  var d = wload(cast[pointer](unsafeAddr inp[24]))
  for _ in 0 ..< 10:
    wQuarterRound(a, b, c, d)
    b = wshuf(b, 1)
    c = wshuf(c, 2)
    d = wshuf(d, 3)
    wQuarterRound(a, b, c, d)
    b = wshuf(b, 3)
    c = wshuf(c, 2)
    d = wshuf(d, 1)
  wstore(cast[pointer](unsafeAddr outp[0]), a)
  wstore(cast[pointer](unsafeAddr outp[8]), b)
  wstore(cast[pointer](unsafeAddr outp[16]), c)
  wstore(cast[pointer](unsafeAddr outp[24]), d)
