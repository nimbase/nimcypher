# SIMD BLAKE2b compression for four messages at once.
#
# Used by `blake2bParallel` (src/nimcypher/algos/blake2b.nim): the four
# messages' compression functions run in parallel, one lane per message. The
# BLAKE2b G function uses only lane-uniform operations (adds, xors and fixed
# 64-bit rotations), so all four lanes execute the same code.
#
# amd64 uses an AVX2 kernel (4 x 64-bit lanes in one 256-bit register);
# arm64 uses a NEON kernel (4 lanes across two uint64x2 registers). Compiled
# only when `features.nimcypher.nimsimd` is defined; see
# `src/nimcypher/algos/blake2b.nim` and the nimcypher.nimble feature block.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../common

when defined(amd64):
  # The SIMD build targets AVX2 on amd64 (same requirement as the ChaCha20
  # kernels; see chacha20.nim), so the whole binary is built with -mavx2.
  {.passC: "-mavx2".}
  import nimsimd/avx2

  # nimsimd does not vendor the unaligned 256-bit store or the four-scalar
  # constructor.
  {.push header: "immintrin.h".}
  func mm256_set_epi64x(a, b, c, d: int64): M256i {.importc: "_mm256_set_epi64x".}
  func mm256_storeu_si256(p: pointer, a: M256i) {.importc: "_mm256_storeu_si256".}
  {.pop.}

  type Vec4* = M256i

  template vadd(a, b: Vec4): Vec4 = mm256_add_epi64(a, b)
  template vxor(a, b: Vec4): Vec4 = mm256_xor_si256(a, b)
  template vand(a, b: Vec4): Vec4 = mm256_and_si256(a, b)
  template vrot(a: Vec4, n: int): Vec4 =
    mm256_or_si256(mm256_srli_epi64(a, int32(n)),
                   mm256_slli_epi64(a, int32(64 - n)))
  template vmk(a, b, c, d: uint64): Vec4 =
    mm256_set_epi64x(cast[int64](d), cast[int64](c), cast[int64](b), cast[int64](a))
  template vstore(p: pointer, v: Vec4) = mm256_storeu_si256(p, v)

elif defined(arm64):
  import nimsimd/neon

  # nimsimd does not vendor the fixed 64-bit shifts (rotate helpers).
  {.push header: "arm_neon.h".}
  func vshrq_n_u64(a: uint64x2, n: int32): uint64x2 {.importc: "vshrq_n_u64".}
  func vshlq_n_u64(a: uint64x2, n: int32): uint64x2 {.importc: "vshlq_n_u64".}
  {.pop.}

  type Vec4* = array[2, uint64x2] # lanes 0,1 | 2,3

  template vadd(a, b: Vec4): Vec4 =
    [vaddq_u64(a[0], b[0]), vaddq_u64(a[1], b[1])]
  template vxor(a, b: Vec4): Vec4 =
    [veorq_u64(a[0], b[0]), veorq_u64(a[1], b[1])]
  template vand(a, b: Vec4): Vec4 =
    [vandq_u64(a[0], b[0]), vandq_u64(a[1], b[1])]
  template vrot(a: Vec4, n: int): Vec4 =
    [vorrq_u64(vshrq_n_u64(a[0], int32(n)), vshlq_n_u64(a[0], int32(64 - n))),
     vorrq_u64(vshrq_n_u64(a[1], int32(n)), vshlq_n_u64(a[1], int32(64 - n)))]
  template vmk(a, b, c, d: uint64): Vec4 =
    [vsetq_lane_u64(b, vmovq_n_u64(a), 1),
     vsetq_lane_u64(d, vmovq_n_u64(c), 1)]
  template vstore(p: pointer, v: Vec4) =
    vst1q_u64(p, v[0])
    vst1q_u64(cast[pointer](cast[uint](p) + 16), v[1])

else:
  {.error: "blake2b_simd requires amd64 (AVX2) or arm64 (NEON).".}

template g4(a, b, c, d, x, y: untyped) =
  a = vadd(a, vadd(b, x))
  d = vrot(vxor(d, a), 32)
  c = vadd(c, d)
  b = vrot(vxor(b, c), 24)
  a = vadd(a, vadd(b, y))
  d = vrot(vxor(d, a), 16)
  c = vadd(c, d)
  b = vrot(vxor(b, c), 63)

proc compress4*(hashes: var array[4, array[8, uint64]],
                offsets: array[4, array[2, uint64]],
                blocks: array[4, array[16, uint64]],
                laneMask: uint64) =
  ## Compress one 128-byte block for up to four BLAKE2b messages in parallel.
  ## Lane k is live when bit k of `laneMask` is set; dead lanes keep their
  ## hash unchanged. `hashes`/`offsets` are the per-message hash and input
  ## offset; `blocks` holds one 128-byte block per message (16 little-endian
  ## 64-bit words each).
  let m0 = if (laneMask and 1'u64) != 0: 0xffffffffffffffff'u64 else: 0'u64
  let m1 = if (laneMask and 2'u64) != 0: 0xffffffffffffffff'u64 else: 0'u64
  let m2 = if (laneMask and 4'u64) != 0: 0xffffffffffffffff'u64 else: 0'u64
  let m3 = if (laneMask and 8'u64) != 0: 0xffffffffffffffff'u64 else: 0'u64
  let maskVec = vmk(m0, m1, m2, m3)

  var m: array[16, Vec4]
  for j in 0 ..< 16:
    m[j] = vmk(blocks[0][j], blocks[1][j], blocks[2][j], blocks[3][j])

  var v0 = vmk(hashes[0][0], hashes[1][0], hashes[2][0], hashes[3][0])
  var v1 = vmk(hashes[0][1], hashes[1][1], hashes[2][1], hashes[3][1])
  var v2 = vmk(hashes[0][2], hashes[1][2], hashes[2][2], hashes[3][2])
  var v3 = vmk(hashes[0][3], hashes[1][3], hashes[2][3], hashes[3][3])
  var v4 = vmk(hashes[0][4], hashes[1][4], hashes[2][4], hashes[3][4])
  var v5 = vmk(hashes[0][5], hashes[1][5], hashes[2][5], hashes[3][5])
  var v6 = vmk(hashes[0][6], hashes[1][6], hashes[2][6], hashes[3][6])
  var v7 = vmk(hashes[0][7], hashes[1][7], hashes[2][7], hashes[3][7])
  var v8 = vmk(blake2bIv[0], blake2bIv[0], blake2bIv[0], blake2bIv[0])
  var v9 = vmk(blake2bIv[1], blake2bIv[1], blake2bIv[1], blake2bIv[1])
  var v10 = vmk(blake2bIv[2], blake2bIv[2], blake2bIv[2], blake2bIv[2])
  var v11 = vmk(blake2bIv[3], blake2bIv[3], blake2bIv[3], blake2bIv[3])
  var v12 = vxor(vmk(blake2bIv[4], blake2bIv[4], blake2bIv[4], blake2bIv[4]),
                 vmk(offsets[0][0], offsets[1][0], offsets[2][0], offsets[3][0]))
  var v13 = vxor(vmk(blake2bIv[5], blake2bIv[5], blake2bIv[5], blake2bIv[5]),
                 vmk(offsets[0][1], offsets[1][1], offsets[2][1], offsets[3][1]))
  var v14 = vmk(blake2bIv[6], blake2bIv[6], blake2bIv[6], blake2bIv[6]) # not last
  var v15 = vmk(blake2bIv[7], blake2bIv[7], blake2bIv[7], blake2bIv[7])

  template blake2Round(r: static int) =
    g4(v0, v4, v8, v12, m[blake2bSigma[r][0]], m[blake2bSigma[r][1]])
    g4(v1, v5, v9, v13, m[blake2bSigma[r][2]], m[blake2bSigma[r][3]])
    g4(v2, v6, v10, v14, m[blake2bSigma[r][4]], m[blake2bSigma[r][5]])
    g4(v3, v7, v11, v15, m[blake2bSigma[r][6]], m[blake2bSigma[r][7]])
    g4(v0, v5, v10, v15, m[blake2bSigma[r][8]], m[blake2bSigma[r][9]])
    g4(v1, v6, v11, v12, m[blake2bSigma[r][10]], m[blake2bSigma[r][11]])
    g4(v2, v7, v8, v13, m[blake2bSigma[r][12]], m[blake2bSigma[r][13]])
    g4(v3, v4, v9, v14, m[blake2bSigma[r][14]], m[blake2bSigma[r][15]])

  blake2Round(0); blake2Round(1); blake2Round(2); blake2Round(3)
  blake2Round(4); blake2Round(5); blake2Round(6); blake2Round(7)
  blake2Round(8); blake2Round(9); blake2Round(10); blake2Round(11)

  var vv: array[16, array[4, uint64]]
  vstore(cast[pointer](unsafeAddr vv[0][0]), v0)
  vstore(cast[pointer](unsafeAddr vv[1][0]), v1)
  vstore(cast[pointer](unsafeAddr vv[2][0]), v2)
  vstore(cast[pointer](unsafeAddr vv[3][0]), v3)
  vstore(cast[pointer](unsafeAddr vv[4][0]), v4)
  vstore(cast[pointer](unsafeAddr vv[5][0]), v5)
  vstore(cast[pointer](unsafeAddr vv[6][0]), v6)
  vstore(cast[pointer](unsafeAddr vv[7][0]), v7)
  vstore(cast[pointer](unsafeAddr vv[8][0]), v8)
  vstore(cast[pointer](unsafeAddr vv[9][0]), v9)
  vstore(cast[pointer](unsafeAddr vv[10][0]), v10)
  vstore(cast[pointer](unsafeAddr vv[11][0]), v11)
  vstore(cast[pointer](unsafeAddr vv[12][0]), v12)
  vstore(cast[pointer](unsafeAddr vv[13][0]), v13)
  vstore(cast[pointer](unsafeAddr vv[14][0]), v14)
  vstore(cast[pointer](unsafeAddr vv[15][0]), v15)

  for k in 0 ..< 4:
    let lk = if (laneMask and (1'u64 shl k)) != 0: 0xffffffffffffffff'u64 else: 0'u64
    for j in 0 ..< 8:
      hashes[k][j] = hashes[k][j] xor (lk and (vv[j][k] xor vv[8 + j][k]))
