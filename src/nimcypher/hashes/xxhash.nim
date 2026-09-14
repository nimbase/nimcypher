# xxHash non-cryptographic hash family: pure Nim, no C dependency.
#
# Implements XXH32, XXH64, XXH3_64bits and XXH3_128bits per the xxHash
# specification v0.2.0 (Cyan4973/xxHash `doc/xxhash_spec.md`), with
# one-shot and streaming APIs mirroring `xxhash.h`
# (`reset/update/digest`, `withSeed/withSecret` variants).
#
# WARNING: xxHash is NOT cryptographic. It provides no collision
# resistance against intentional attacks and must never be used for
# signatures, MACs, or password hashing. Use BLAKE2b or SHA-2 instead.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

{.push checks: off.}

const
  XxhSecretSizeMin* = 136
  XxhSecretDefaultSize* = 192
  Xxh3MidsizeMax* = 240

type
  Xxh128* = object
    ## 128-bit XXH3 result: lower and higher 64-bit halves.
    lo*: uint64
    hi*: uint64

  Xxh32State* = object
    acc: array[4, uint32]
    buf: array[16, byte]
    bufLen: int
    totalLen: uint64
    seed: uint32

  Xxh64State* = object
    acc: array[4, uint64]
    buf: array[32, byte]
    bufLen: int
    totalLen: uint64
    seed: uint64

  Xxh3Kind* = enum
    xxh3_64
    xxh3_128

  Xxh3State* = object
    ## Streaming XXH3 state. Buffers input and hashes it at digest
    ## time, so results match the one-shot form for any chunking.
    kind: Xxh3Kind
    seed: uint64
    secret: seq[byte]
    useSecret: bool
    buf: seq[byte]

const
  P32_1 = 0x9E3779B1'u32
  P32_2 = 0x85EBCA77'u32
  P32_3 = 0xC2B2AE3D'u32
  P32_4 = 0x27D4EB2F'u32
  P32_5 = 0x165667B1'u32

  P64_1 = 0x9E3779B185EBCA87'u64
  P64_2 = 0xC2B2AE3D27D4EB4F'u64
  P64_3 = 0x165667B19E3779F9'u64
  P64_4 = 0x85EBCA77C2B2AE63'u64
  P64_5 = 0x27D4EB2F165667C5'u64
  PRIME_MX1 = 0x165667919E3779F9'u64
  PRIME_MX2 = 0x9FB21C651E98DF25'u64

# Default 192-byte secret (spec, little-endian reads everywhere).
const defaultSecret: array[192, byte] = [
  0xB8'u8, 0xFE, 0x6C, 0x39, 0x23, 0xA4, 0x4B, 0xBE,
  0x7C, 0x01, 0x81, 0x2C, 0xF7, 0x21, 0xAD, 0x1C,
  0xDE, 0xD4, 0x6D, 0xE9, 0x83, 0x90, 0x97, 0xDB,
  0x72, 0x40, 0xA4, 0xA4, 0xB7, 0xB3, 0x67, 0x1F,
  0xCB, 0x79, 0xE6, 0x4E, 0xCC, 0xC0, 0xE5, 0x78,
  0x82, 0x5A, 0xD0, 0x7D, 0xCC, 0xFF, 0x72, 0x21,
  0xB8, 0x08, 0x46, 0x74, 0xF7, 0x43, 0x24, 0x8E,
  0xE0, 0x35, 0x90, 0xE6, 0x81, 0x3A, 0x26, 0x4C,
  0x3C, 0x28, 0x52, 0xBB, 0x91, 0xC3, 0x00, 0xCB,
  0x88, 0xD0, 0x65, 0x8B, 0x1B, 0x53, 0x2E, 0xA3,
  0x71, 0x64, 0x48, 0x97, 0xA2, 0x0D, 0xF9, 0x4E,
  0x38, 0x19, 0xEF, 0x46, 0xA9, 0xDE, 0xAC, 0xD8,
  0xA8, 0xFA, 0x76, 0x3F, 0xE3, 0x9C, 0x34, 0x3F,
  0xF9, 0xDC, 0xBB, 0xC7, 0xC7, 0x0B, 0x4F, 0x1D,
  0x8A, 0x51, 0xE0, 0x4B, 0xCD, 0xB4, 0x59, 0x31,
  0xC8, 0x9F, 0x7E, 0xC9, 0xD9, 0x78, 0x73, 0x64,
  0xEA, 0xC5, 0xAC, 0x83, 0x34, 0xD3, 0xEB, 0xC3,
  0xC5, 0x81, 0xA0, 0xFF, 0xFA, 0x13, 0x63, 0xEB,
  0x17, 0x0D, 0xDD, 0x51, 0xB7, 0xF0, 0xDA, 0x49,
  0xD3, 0x16, 0x55, 0x26, 0x29, 0xD4, 0x68, 0x9E,
  0x2B, 0x16, 0xBE, 0x58, 0x7D, 0x47, 0xA1, 0xFC,
  0x8F, 0xF8, 0xB8, 0xD1, 0x7A, 0xD0, 0x31, 0xCE,
  0x45, 0xCB, 0x3A, 0x8F, 0x95, 0x16, 0x04, 0x28,
  0xAF, 0xD7, 0xFB, 0xCA, 0xBB, 0x4B, 0x40, 0x7E,
]

proc `==`*(a, b: Xxh128): bool {.inline.} =
  a.lo == b.lo and a.hi == b.hi

# Scalar helpers (all multi-byte reads are little-endian).

proc rotl32(x: uint32, r: int): uint32 {.inline.} =
  (x shl r) or (x shr (32 - r))

proc rotl64(x: uint64, r: int): uint64 {.inline.} =
  (x shl r) or (x shr (64 - r))

proc read32le(d: openArray[byte], off: int): uint32 {.inline.} =
  uint32(d[off]) or (uint32(d[off+1]) shl 8) or
    (uint32(d[off+2]) shl 16) or (uint32(d[off+3]) shl 24)

proc read64le(d: openArray[byte], off: int): uint64 {.inline.} =
  uint64(read32le(d, off)) or (uint64(read32le(d, off+4)) shl 32)

proc write64le(d: var openArray[byte], off: int, v: uint64) {.inline.} =
  d[off] = byte(v)
  d[off+1] = byte(v shr 8)
  d[off+2] = byte(v shr 16)
  d[off+3] = byte(v shr 24)
  d[off+4] = byte(v shr 32)
  d[off+5] = byte(v shr 40)
  d[off+6] = byte(v shr 48)
  d[off+7] = byte(v shr 56)

proc bswap32(x: uint32): uint32 {.inline.} =
  ((x and 0xFF'u32) shl 24) or ((x and 0xFF00'u32) shl 8) or
    ((x shr 8) and 0xFF00'u32) or ((x shr 24) and 0xFF'u32)

proc bswap64(x: uint64): uint64 {.inline.} =
  (uint64(bswap32(uint32(x))) shl 32) or uint64(bswap32(uint32(x shr 32)))

proc mul128(a, b: uint64, lo, hi: var uint64) {.inline.} =
  ## Full 64x64 to 128-bit multiply via 32-bit halves.
  let a0 = a and 0xFFFFFFFF'u64
  let a1 = a shr 32
  let b0 = b and 0xFFFFFFFF'u64
  let b1 = b shr 32
  let p0 = a0 * b0
  let p1 = a0 * b1
  let p2 = a1 * b0
  let p3 = a1 * b1
  var mid = (p0 shr 32) + (p1 and 0xFFFFFFFF'u64) + (p2 and 0xFFFFFFFF'u64)
  # mid cannot wrap: (p0 shr 32) + p1lo + p2lo < 2^32 + 2^33 < 2^64,
  # so (mid shr 32) is exactly the carry into the high word.
  lo = (p0 and 0xFFFFFFFF'u64) or (mid shl 32)
  hi = p3 + (p1 shr 32) + (p2 shr 32) + (mid shr 32)

proc mul128Fold(a, b: uint64): uint64 {.inline.} =
  var lo, hi: uint64
  mul128(a, b, lo, hi)
  lo xor hi

# XXH32.

proc xxh32Round(acc, lane: uint32): uint32 {.inline.} =
  rotl32(acc + lane * P32_2, 13) * P32_1

proc xxh32Avalanche(h: uint32): uint32 {.inline.} =
  result = h xor (h shr 15)
  result = result * P32_2
  result = result xor (result shr 13)
  result = result * P32_3
  result = result xor (result shr 16)

proc xxh32Converge(v1, v2, v3, v4: uint32): uint32 {.inline.} =
  rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)

proc xxh32Tail(h: uint32, data: openArray[byte], off: int): uint32 =
  var acc = h
  var p = off
  while p + 4 <= data.len:
    acc += read32le(data, p) * P32_3
    acc = rotl32(acc, 17) * P32_4
    p += 4
  while p < data.len:
    acc += uint32(data[p]) * P32_5
    acc = rotl32(acc, 11) * P32_1
    inc p
  acc

proc xxh32*(data: openArray[byte], seed: uint32 = 0): uint32 =
  ## One-shot XXH32. `seed` alters the output predictably.
  var h: uint32
  var off = 0
  if data.len >= 16:
    var v1 = seed + P32_1 + P32_2
    var v2 = seed + P32_2
    var v3 = seed
    var v4 = seed - P32_1
    while off + 16 <= data.len:
      v1 = xxh32Round(v1, read32le(data, off))
      v2 = xxh32Round(v2, read32le(data, off+4))
      v3 = xxh32Round(v3, read32le(data, off+8))
      v4 = xxh32Round(v4, read32le(data, off+12))
      off += 16
    h = xxh32Converge(v1, v2, v3, v4)
  else:
    h = seed + P32_5
  h += uint32(data.len)
  result = xxh32Avalanche(xxh32Tail(h, data, off))

proc reset*(state: var Xxh32State, seed: uint32 = 0) =
  state.acc[0] = seed + P32_1 + P32_2
  state.acc[1] = seed + P32_2
  state.acc[2] = seed
  state.acc[3] = seed - P32_1
  state.bufLen = 0
  state.totalLen = 0
  state.seed = seed

proc update*(state: var Xxh32State, data: openArray[byte]) =
  if data.len == 0:
    return
  var off = 0
  var left = data.len
  if state.bufLen > 0:
    let need = 16 - state.bufLen
    let take = min(need, left)
    for i in 0 ..< take:
      state.buf[state.bufLen + i] = data[off + i]
    state.bufLen += take
    off += take
    left -= take
    state.totalLen += uint64(take)
    if state.bufLen == 16:
      state.acc[0] = xxh32Round(state.acc[0], read32le(state.buf, 0))
      state.acc[1] = xxh32Round(state.acc[1], read32le(state.buf, 4))
      state.acc[2] = xxh32Round(state.acc[2], read32le(state.buf, 8))
      state.acc[3] = xxh32Round(state.acc[3], read32le(state.buf, 12))
      state.bufLen = 0
  while left >= 16:
    state.acc[0] = xxh32Round(state.acc[0], read32le(data, off))
    state.acc[1] = xxh32Round(state.acc[1], read32le(data, off+4))
    state.acc[2] = xxh32Round(state.acc[2], read32le(data, off+8))
    state.acc[3] = xxh32Round(state.acc[3], read32le(data, off+12))
    off += 16
    left -= 16
    state.totalLen += 16
  if left > 0:
    for i in 0 ..< left:
      state.buf[i] = data[off + i]
    state.bufLen = left
    state.totalLen += uint64(left)

proc digest*(state: Xxh32State): uint32 =
  var h: uint32
  if state.totalLen >= 16:
    h = xxh32Converge(state.acc[0], state.acc[1], state.acc[2], state.acc[3])
  else:
    h = state.seed + P32_5
  h += uint32(state.totalLen)
  if state.bufLen > 0:
    h = xxh32Tail(h, state.buf.toOpenArray(0, state.bufLen - 1), 0)
  result = xxh32Avalanche(h)

# XXH64.

proc xxh64Round(acc, lane: uint64): uint64 {.inline.} =
  rotl64(acc + lane * P64_2, 31) * P64_1

proc xxh64Merge(acc, accN: uint64): uint64 {.inline.} =
  result = (acc xor xxh64Round(0, accN)) * P64_1 + P64_4

proc xxh64Avalanche(h: uint64): uint64 {.inline.} =
  result = h xor (h shr 33)
  result = result * P64_2
  result = result xor (result shr 29)
  result = result * P64_3
  result = result xor (result shr 32)

proc xxh64Tail(h: uint64, data: openArray[byte], off: int): uint64 =
  var acc = h
  var p = off
  while p + 8 <= data.len:
    acc = rotl64(acc xor xxh64Round(0, read64le(data, p)), 27) * P64_1 + P64_4
    p += 8
  if p + 4 <= data.len:
    acc = rotl64(acc xor (uint64(read32le(data, p)) * P64_1), 23) * P64_2 + P64_3
    p += 4
  while p < data.len:
    acc = rotl64(acc xor (uint64(data[p]) * P64_5), 11) * P64_1
    inc p
  acc

proc xxh64*(data: openArray[byte], seed: uint64 = 0): uint64 =
  ## One-shot XXH64. `seed` alters the output predictably.
  var h: uint64
  var off = 0
  if data.len >= 32:
    var v1 = seed + P64_1 + P64_2
    var v2 = seed + P64_2
    var v3 = seed
    var v4 = seed - P64_1
    while off + 32 <= data.len:
      v1 = xxh64Round(v1, read64le(data, off))
      v2 = xxh64Round(v2, read64le(data, off+8))
      v3 = xxh64Round(v3, read64le(data, off+16))
      v4 = xxh64Round(v4, read64le(data, off+24))
      off += 32
    h = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)
    h = xxh64Merge(h, v1)
    h = xxh64Merge(h, v2)
    h = xxh64Merge(h, v3)
    h = xxh64Merge(h, v4)
  else:
    h = seed + P64_5
  h += uint64(data.len)
  result = xxh64Avalanche(xxh64Tail(h, data, off))

proc reset*(state: var Xxh64State, seed: uint64 = 0) =
  state.acc[0] = seed + P64_1 + P64_2
  state.acc[1] = seed + P64_2
  state.acc[2] = seed
  state.acc[3] = seed - P64_1
  state.bufLen = 0
  state.totalLen = 0
  state.seed = seed

proc update*(state: var Xxh64State, data: openArray[byte]) =
  if data.len == 0:
    return
  var off = 0
  var left = data.len
  if state.bufLen > 0:
    let need = 32 - state.bufLen
    let take = min(need, left)
    for i in 0 ..< take:
      state.buf[state.bufLen + i] = data[off + i]
    state.bufLen += take
    off += take
    left -= take
    state.totalLen += uint64(take)
    if state.bufLen == 32:
      state.acc[0] = xxh64Round(state.acc[0], read64le(state.buf, 0))
      state.acc[1] = xxh64Round(state.acc[1], read64le(state.buf, 8))
      state.acc[2] = xxh64Round(state.acc[2], read64le(state.buf, 16))
      state.acc[3] = xxh64Round(state.acc[3], read64le(state.buf, 24))
      state.bufLen = 0
  while left >= 32:
    state.acc[0] = xxh64Round(state.acc[0], read64le(data, off))
    state.acc[1] = xxh64Round(state.acc[1], read64le(data, off+8))
    state.acc[2] = xxh64Round(state.acc[2], read64le(data, off+16))
    state.acc[3] = xxh64Round(state.acc[3], read64le(data, off+24))
    off += 32
    left -= 32
    state.totalLen += 32
  if left > 0:
    for i in 0 ..< left:
      state.buf[i] = data[off + i]
    state.bufLen = left
    state.totalLen += uint64(left)

proc digest*(state: Xxh64State): uint64 =
  var h: uint64
  if state.totalLen >= 32:
    h = rotl64(state.acc[0], 1) + rotl64(state.acc[1], 7) +
        rotl64(state.acc[2], 12) + rotl64(state.acc[3], 18)
    h = xxh64Merge(h, state.acc[0])
    h = xxh64Merge(h, state.acc[1])
    h = xxh64Merge(h, state.acc[2])
    h = xxh64Merge(h, state.acc[3])
  else:
    h = state.seed + P64_5
  h += state.totalLen
  if state.bufLen > 0:
    h = xxh64Tail(h, state.buf.toOpenArray(0, state.bufLen - 1), 0)
  result = xxh64Avalanche(h)

# XXH3 shared pieces.

proc xxh3Avalanche(x: uint64): uint64 {.inline.} =
  result = x xor (x shr 37)
  result = result * PRIME_MX1
  result = result xor (result shr 32)

proc xxh3Avalanche64(x: uint64): uint64 {.inline.} =
  result = x xor (x shr 33)
  result = result * P64_2
  result = result xor (result shr 29)
  result = result * P64_3
  result = result xor (result shr 32)

proc deriveSecret(seed: uint64, secret: var openArray[byte]) =
  ## Derive a 192-byte secret from `seed` and the default secret.
  for i in 0 ..< 24:
    var w = read64le(defaultSecret, i * 8)
    if (i and 1) == 0:
      w += seed
    else:
      w -= seed
    write64le(secret, i * 8, w)

proc checkSecret(secret: openArray[byte]) {.inline.} =
  if secret.len < XxhSecretSizeMin:
    raise newException(ValueError,
      "xxHash secret too short: need at least " & $XxhSecretSizeMin & " bytes")

proc mixStep(data: openArray[byte], dOff: int,
             secret: openArray[byte], sOff: int, seed: uint64): uint64 {.inline.} =
  let d0 = read64le(data, dOff)
  let d1 = read64le(data, dOff+8)
  let s0 = read64le(secret, sOff)
  let s1 = read64le(secret, sOff+8)
  mul128Fold(d0 xor (s0 + seed), d1 xor (s1 - seed))

# Small inputs (0..16).

proc xxh3_64_0to16(data: openArray[byte],
                   secret: openArray[byte], seed: uint64): uint64 =
  let n = data.len
  if n == 0:
    let s0 = read64le(secret, 56)
    let s1 = read64le(secret, 64)
    return xxh3Avalanche64(seed xor s0 xor s1)
  if n <= 3:
    let last = uint32(data[n-1])
    let first = uint32(data[0])
    let mid = uint32(data[n shr 1])
    let combined = last or (uint32(n) shl 8) or (first shl 16) or (mid shl 24)
    let s0 = read32le(secret, 0)
    let s1 = read32le(secret, 4)
    let value = (uint64(s0 xor s1) + seed) xor uint64(combined)
    return xxh3Avalanche64(value)
  if n <= 8:
    let inputFirst = read32le(data, 0)
    let inputLast = read32le(data, n-4)
    let s0 = read64le(secret, 8)
    let s1 = read64le(secret, 16)
    let modifiedSeed = seed xor (uint64(bswap32(uint32(seed))) shl 32)
    let combined = uint64(inputLast) or (uint64(inputFirst) shl 32)
    var value = ((s0 xor s1) - modifiedSeed) xor combined
    value = value xor rotl64(value, 49) xor rotl64(value, 24)
    value = value * PRIME_MX2
    value = value xor ((value shr 35) + uint64(n))
    value = value * PRIME_MX2
    value = value xor (value shr 28)
    return value
  # 9..16
  let inputFirst = read64le(data, 0)
  let inputLast = read64le(data, n-8)
  let s0 = read64le(secret, 24)
  let s1 = read64le(secret, 32)
  let s2 = read64le(secret, 40)
  let s3 = read64le(secret, 48)
  let lo = ((s0 xor s1) + seed) xor inputFirst
  let hi = ((s2 xor s3) - seed) xor inputLast
  var mLo, mHi: uint64
  mul128(lo, hi, mLo, mHi)
  let value = uint64(n) + bswap64(lo) + hi + (mLo xor mHi)
  result = xxh3Avalanche(value)

proc xxh3_128_0to16(data: openArray[byte],
                    secret: openArray[byte], seed: uint64): Xxh128 =
  let n = data.len
  if n == 0:
    let s0 = read64le(secret, 64)
    let s1 = read64le(secret, 72)
    let s2 = read64le(secret, 80)
    let s3 = read64le(secret, 88)
    return Xxh128(lo: xxh3Avalanche64(seed xor s0 xor s1),
                  hi: xxh3Avalanche64(seed xor s2 xor s3))
  if n <= 3:
    let last = uint32(data[n-1])
    let first = uint32(data[0])
    let mid = uint32(data[n shr 1])
    let combined = last or (uint32(n) shl 8) or (first shl 16) or (mid shl 24)
    let s0 = read32le(secret, 0)
    let s1 = read32le(secret, 4)
    let s2 = read32le(secret, 8)
    let s3 = read32le(secret, 12)
    let lo = (uint64(s0 xor s1) + seed) xor uint64(combined)
    let hi = (uint64(s2 xor s3) - seed) xor
      uint64(rotl32(bswap32(combined), 13))
    return Xxh128(lo: xxh3Avalanche64(lo), hi: xxh3Avalanche64(hi))
  if n <= 8:
    let inputFirst = read32le(data, 0)
    let inputLast = read32le(data, n-4)
    let s0 = read64le(secret, 16)
    let s1 = read64le(secret, 24)
    let modifiedSeed = seed xor (uint64(bswap32(uint32(seed))) shl 32)
    let combined = uint64(inputFirst) or (uint64(inputLast) shl 32)
    let value = ((s0 xor s1) + modifiedSeed) xor combined
    var mLo, mHi: uint64
    mul128(value, P64_1 + (uint64(n) shl 2), mLo, mHi)
    var hi = mHi + (mLo shl 1)
    var lo = mLo xor (hi shr 3)
    lo = lo xor (lo shr 35)
    lo = lo * PRIME_MX2
    lo = lo xor (lo shr 28)
    hi = xxh3Avalanche(hi)
    return Xxh128(lo: lo, hi: hi)
  # 9..16
  let inputFirst = read64le(data, 0)
  let inputLast = read64le(data, n-8)
  let s0 = read64le(secret, 32)
  let s1 = read64le(secret, 40)
  let s2 = read64le(secret, 48)
  let s3 = read64le(secret, 56)
  let val1 = ((s0 xor s1) - seed) xor inputFirst xor inputLast
  let val2 = ((s2 xor s3) + seed) xor inputLast
  var mLo, mHi: uint64
  mul128(val1, P64_1, mLo, mHi)
  var lo = mLo + (uint64(n - 1) shl 54)
  var hi = mHi + (uint64(val2 shr 32) shl 32) +
    uint64(uint32(val2)) * uint64(P32_2)
  lo = lo xor bswap64(hi)
  var m2Lo, m2Hi: uint64
  mul128(lo, P64_2, m2Lo, m2Hi)
  lo = m2Lo
  hi = m2Hi + hi * P64_2
  result = Xxh128(lo: xxh3Avalanche(lo), hi: xxh3Avalanche(hi))

# Medium inputs (17..240).

proc xxh3_64_17to128(data: openArray[byte],
                     secret: openArray[byte], seed: uint64): uint64 =
  let n = data.len
  var acc = uint64(n) * P64_1
  let numRounds = ((n - 1) shr 5) + 1
  var i = numRounds - 1
  while true:
    let offStart = i * 16
    let offEnd = n - i * 16 - 16
    acc += mixStep(data, offStart, secret, i * 32, seed)
    acc += mixStep(data, offEnd, secret, i * 32 + 16, seed)
    if i == 0:
      break
    dec i
  xxh3Avalanche(acc)

proc xxh3_128_17to128(data: openArray[byte],
                      secret: openArray[byte], seed: uint64): Xxh128 =
  let n = data.len
  var acc0 = uint64(n) * P64_1
  var acc1: uint64 = 0
  let numRounds = ((n - 1) shr 5) + 1
  var i = numRounds - 1
  while true:
    let offStart = i * 16
    let offEnd = n - i * 16 - 16
    let d1a = read64le(data, offStart)
    let d1b = read64le(data, offStart+8)
    let d2a = read64le(data, offEnd)
    let d2b = read64le(data, offEnd+8)
    acc0 += mixStep(data, offStart, secret, i * 32, seed)
    acc1 += mixStep(data, offEnd, secret, i * 32 + 16, seed)
    acc0 = acc0 xor (d2a + d2b)
    acc1 = acc1 xor (d1a + d1b)
    if i == 0:
      break
    dec i
  let lo = acc0 + acc1
  let hi = acc0 * P64_1 + acc1 * P64_4 + (uint64(n) - seed) * P64_2
  Xxh128(lo: xxh3Avalanche(lo), hi: 0'u64 - xxh3Avalanche(hi))

proc xxh3_64_129to240(data: openArray[byte],
                      secret: openArray[byte], seed: uint64): uint64 =
  let n = data.len
  var acc = uint64(n) * P64_1
  let numChunks = n shr 4
  for i in 0 ..< 8:
    acc += mixStep(data, i * 16, secret, i * 16, seed)
  acc = xxh3Avalanche(acc)
  for i in 8 ..< numChunks:
    acc += mixStep(data, i * 16, secret, (i - 8) * 16 + 3, seed)
  acc += mixStep(data, n - 16, secret, 119, seed)
  xxh3Avalanche(acc)

proc xxh3_128_129to240(data: openArray[byte],
                       secret: openArray[byte], seed: uint64): Xxh128 =
  let n = data.len
  var acc0 = uint64(n) * P64_1
  var acc1: uint64 = 0
  let numChunks = n shr 5
  for i in 0 ..< 4:
    let dOff = i * 32
    let sOff = i * 32
    acc0 += mixStep(data, dOff, secret, sOff, seed)
    acc1 += mixStep(data, dOff+16, secret, sOff+16, seed)
    acc0 = acc0 xor (read64le(data, dOff+16) + read64le(data, dOff+24))
    acc1 = acc1 xor (read64le(data, dOff) + read64le(data, dOff+8))
  acc0 = xxh3Avalanche(acc0)
  acc1 = xxh3Avalanche(acc1)
  for i in 4 ..< numChunks:
    let dOff = i * 32
    let sOff = (i - 4) * 32 + 3
    acc0 += mixStep(data, dOff, secret, sOff, seed)
    acc1 += mixStep(data, dOff+16, secret, sOff+16, seed)
    acc0 = acc0 xor (read64le(data, dOff+16) + read64le(data, dOff+24))
    acc1 = acc1 xor (read64le(data, dOff) + read64le(data, dOff+8))
  # Final pair uses swapped chunk order and negated seed per spec:
  # data1 = last 16 bytes, data2 = previous 16 bytes.
  let negSeed = 0'u64 - seed
  acc0 += mixStep(data, n - 16, secret, 103, negSeed)
  acc1 += mixStep(data, n - 32, secret, 103 + 16, negSeed)
  acc0 = acc0 xor (read64le(data, n - 32) + read64le(data, n - 24))
  acc1 = acc1 xor (read64le(data, n - 16) + read64le(data, n - 8))
  let lo = acc0 + acc1
  let hi = acc0 * P64_1 + acc1 * P64_4 + (uint64(n) - seed) * P64_2
  Xxh128(lo: xxh3Avalanche(lo), hi: 0'u64 - xxh3Avalanche(hi))

# Large inputs (> 240).

proc xxh3Accumulate(acc: var array[8, uint64],
                    stripe: openArray[byte], sOff: int,
                    secret: openArray[byte]) {.inline.} =
  for i in 0 ..< 8:
    let lane = read64le(stripe, i * 8)
    let s = read64le(secret, sOff + i * 8)
    let v = lane xor s
    acc[i xor 1] += lane
    acc[i] += (v and 0xFFFFFFFF'u64) * (v shr 32)

proc xxh3Scramble(acc: var array[8, uint64],
                  secret: openArray[byte]) {.inline.} =
  let base = secret.len - 64
  for i in 0 ..< 8:
    acc[i] = acc[i] xor (acc[i] shr 47)
    acc[i] = acc[i] xor read64le(secret, base + i * 8)
    acc[i] = acc[i] * uint64(P32_1)

proc xxh3FinalMerge(acc: array[8, uint64], initVal: uint64,
                    secret: openArray[byte], sOff: int): uint64 =
  var res = initVal
  for i in 0 ..< 4:
    let a = acc[i*2] xor read64le(secret, sOff + i * 16)
    let b = acc[i*2+1] xor read64le(secret, sOff + i * 16 + 8)
    res += mul128Fold(a, b)
  xxh3Avalanche(res)

proc xxh3_64_large(data: openArray[byte],
                   secret: openArray[byte]): uint64 =
  let n = data.len
  let stripesPerBlock = (secret.len - 64) div 8
  let blockSize = 64 * stripesPerBlock
  var acc: array[8, uint64] = [
    uint64(P32_3), P64_1, P64_2, P64_3, P64_4, uint64(P32_2), P64_5,
    uint64(P32_1)]
  var off = 0
  var remaining = n
  while remaining > blockSize:
    for s in 0 ..< stripesPerBlock:
      xxh3Accumulate(acc, data.toOpenArray(off + s * 64, off + s * 64 + 63),
                     s * 8, secret)
    xxh3Scramble(acc, secret)
    off += blockSize
    remaining -= blockSize
  # Last block: all but the final stripe, then the last 64 bytes
  # (which may overlap earlier stripes).
  let nFull = (remaining - 1) div 64
  for s in 0 ..< nFull:
    xxh3Accumulate(acc, data.toOpenArray(off + s * 64, off + s * 64 + 63),
                   s * 8, secret)
  xxh3Accumulate(acc, data.toOpenArray(n - 64, n - 1),
                 secret.len - 71, secret)
  xxh3FinalMerge(acc, uint64(n) * P64_1, secret, 11)

proc xxh3_128_large(data: openArray[byte],
                    secret: openArray[byte]): Xxh128 =
  let n = data.len
  let stripesPerBlock = (secret.len - 64) div 8
  let blockSize = 64 * stripesPerBlock
  var acc: array[8, uint64] = [
    uint64(P32_3), P64_1, P64_2, P64_3, P64_4, uint64(P32_2), P64_5,
    uint64(P32_1)]
  var off = 0
  var remaining = n
  while remaining > blockSize:
    for s in 0 ..< stripesPerBlock:
      xxh3Accumulate(acc, data.toOpenArray(off + s * 64, off + s * 64 + 63),
                     s * 8, secret)
    xxh3Scramble(acc, secret)
    off += blockSize
    remaining -= blockSize
  let nFull = (remaining - 1) div 64
  for s in 0 ..< nFull:
    xxh3Accumulate(acc, data.toOpenArray(off + s * 64, off + s * 64 + 63),
                   s * 8, secret)
  xxh3Accumulate(acc, data.toOpenArray(n - 64, n - 1),
                 secret.len - 71, secret)
  Xxh128(lo: xxh3FinalMerge(acc, uint64(n) * P64_1, secret, 11),
         hi: xxh3FinalMerge(acc, not (uint64(n) * P64_2),
                            secret, secret.len - 75))

# One-shot XXH3 entry points.

proc xxh3_64_withSecret*(data: openArray[byte],
                         secret: openArray[byte]): uint64 =
  ## One-shot XXH3_64bits with a custom secret (>= 136 bytes).
  checkSecret(secret)
  let n = data.len
  if n <= 16:
    return xxh3_64_0to16(data, secret, 0)
  if n <= 128:
    var acc = uint64(n) * P64_1
    let numRounds = ((n - 1) shr 5) + 1
    var i = numRounds - 1
    while true:
      acc += mixStep(data, i * 16, secret, i * 32, 0)
      acc += mixStep(data, n - i * 16 - 16, secret, i * 32 + 16, 0)
      if i == 0:
        break
      dec i
    return xxh3Avalanche(acc)
  if n <= 240:
    return xxh3_64_129to240(data, secret, 0)
  result = xxh3_64_large(data, secret)

proc xxh3_64bits_withSeed*(data: openArray[byte], seed: uint64): uint64 =
  ## One-shot seeded XXH3_64bits. Short inputs use the default secret
  ## plus `seed`; only large inputs derive a secret from `seed`.
  let n = data.len
  if n <= 16:
    return xxh3_64_0to16(data, defaultSecret, seed)
  if n <= 128:
    return xxh3_64_17to128(data, defaultSecret, seed)
  if n <= 240:
    return xxh3_64_129to240(data, defaultSecret, seed)
  var sec: array[192, byte]
  deriveSecret(seed, sec)
  result = xxh3_64_large(data, sec)

proc xxh3_64bits*(data: openArray[byte]): uint64 =
  ## One-shot unseeded XXH3_64bits (same as seed 0).
  result = xxh3_64bits_withSeed(data, 0)

proc xxh3_64bits_withSecretAndSeed*(data: openArray[byte],
                                    secret: openArray[byte],
                                    seed: uint64): uint64 =
  ## `seed` for short inputs (<= 240 bytes), `secret` for large inputs.
  checkSecret(secret)
  if data.len <= Xxh3MidsizeMax:
    return xxh3_64bits_withSeed(data, seed)
  result = xxh3_64_withSecret(data, secret)

proc xxh3_128_withSecret*(data: openArray[byte],
                          secret: openArray[byte]): Xxh128 =
  ## One-shot XXH3_128bits with a custom secret (>= 136 bytes).
  checkSecret(secret)
  let n = data.len
  if n <= 16:
    return xxh3_128_0to16(data, secret, 0)
  if n <= 128:
    let numRounds = ((n - 1) shr 5) + 1
    var acc0 = uint64(n) * P64_1
    var acc1: uint64 = 0
    var i = numRounds - 1
    while true:
      let os = i * 16
      let oe = n - i * 16 - 16
      acc0 += mixStep(data, os, secret, i * 32, 0)
      acc1 += mixStep(data, oe, secret, i * 32 + 16, 0)
      acc0 = acc0 xor (read64le(data, oe) + read64le(data, oe+8))
      acc1 = acc1 xor (read64le(data, os) + read64le(data, os+8))
      if i == 0:
        break
      dec i
    let lo = acc0 + acc1
    let hi = acc0 * P64_1 + acc1 * P64_4 + uint64(n) * P64_2
    return Xxh128(lo: xxh3Avalanche(lo), hi: 0'u64 - xxh3Avalanche(hi))
  if n <= 240:
    return xxh3_128_129to240(data, secret, 0)
  result = xxh3_128_large(data, secret)

proc xxh3_128bits_withSeed*(data: openArray[byte], seed: uint64): Xxh128 =
  ## One-shot seeded XXH3_128bits. Short inputs use the default secret
  ## plus `seed`; only large inputs derive a secret from `seed`.
  let n = data.len
  if n <= 16:
    return xxh3_128_0to16(data, defaultSecret, seed)
  if n <= 128:
    return xxh3_128_17to128(data, defaultSecret, seed)
  if n <= 240:
    return xxh3_128_129to240(data, defaultSecret, seed)
  var sec: array[192, byte]
  deriveSecret(seed, sec)
  result = xxh3_128_large(data, sec)

proc xxh3_128bits*(data: openArray[byte]): Xxh128 =
  ## One-shot unseeded XXH3_128bits (same as seed 0).
  result = xxh3_128bits_withSeed(data, 0)

proc xxh128*(data: openArray[byte], seed: uint64 = 0): Xxh128 =
  ## Alias of `xxh3_128bits_withSeed` (mirrors `XXH128()`).
  result = xxh3_128bits_withSeed(data, seed)

proc xxh3_128bits_withSecretAndSeed*(data: openArray[byte],
                                     secret: openArray[byte],
                                     seed: uint64): Xxh128 =
  ## `seed` for short inputs (<= 240 bytes), `secret` for large inputs.
  checkSecret(secret)
  if data.len <= Xxh3MidsizeMax:
    return xxh3_128bits_withSeed(data, seed)
  result = xxh3_128_withSecret(data, secret)

proc generateSecret*(secret: var openArray[byte],
                     customSeed: openArray[byte]) =
  ## Derive a high-entropy secret from `customSeed`
  ## (mirrors `XXH3_generateSecret()`). `secret` must hold at least
  ## 136 bytes; only the first `secret.len` bytes are written.
  if secret.len < XxhSecretSizeMin:
    raise newException(ValueError, "secret buffer too short")
  if customSeed.len == 0:
    raise newException(ValueError, "custom seed must not be empty")
  # Mix the custom seed into the default secret in 16-byte blocks.
  var i = 0
  var acc: uint64 = uint64(secret.len)
  while i < secret.len:
    let take = min(16, secret.len - i)
    var blk: array[16, byte]
    for j in 0 ..< take:
      blk[j] = customSeed[(i + j) mod customSeed.len]
    let d0 = read64le(blk, 0)
    let d1 = if take > 8: read64le(blk, 8)
             else: uint64(take) * 0x9E3779B97F4A7C15'u64
    let s0 = read64le(defaultSecret, i mod 192)
    let s1 = read64le(defaultSecret, (i + 8) mod 192)
    acc += mixStep(blk, 0, defaultSecret, (i mod 128), acc)
    var mLo, mHi: uint64
    mul128(d0 + s0 + acc, d1 + s1 - acc, mLo, mHi)
    let w0 = mLo xor mHi xor acc
    mul128(d1 + s1 + acc + 0x9E3779B97F4A7C15'u64,
           d0 + s0 - acc + 0xBF58476D1CE4E5B9'u64, mLo, mHi)
    let w1 = mLo xor mHi xor (acc * 2)
    let out0 = min(8, take)
    for j in 0 ..< out0:
      secret[i + j] = byte(w0 shr (8 * j))
    if take > 8:
      for j in 0 ..< take - 8:
        secret[i + 8 + j] = byte(w1 shr (8 * j))
    i += take

# Streaming XXH3.

proc resetXxh3*(state: var Xxh3State, kind: Xxh3Kind, seed: uint64 = 0) =
  state.kind = kind
  state.seed = seed
  state.secret = @[]
  state.useSecret = false
  state.buf = @[]

proc resetXxh3WithSecret*(state: var Xxh3State, kind: Xxh3Kind,
                          secret: openArray[byte]) =
  checkSecret(secret)
  state.kind = kind
  state.seed = 0
  state.secret = @(secret.toOpenArray(0, secret.len - 1))
  state.useSecret = true
  state.buf = @[]

proc update*(state: var Xxh3State, data: openArray[byte]) =
  for b in data:
    state.buf.add(b)

proc digest64*(state: Xxh3State): uint64 =
  if state.kind != xxh3_64:
    raise newException(ValueError, "XXH3 state holds a 128-bit hash")
  if state.useSecret:
    if state.buf.len <= Xxh3MidsizeMax:
      # Short inputs use the seed alone (default secret), like withSeed.
      return xxh3_64bits_withSeed(state.buf, state.seed)
    return xxh3_64_withSecret(state.buf, state.secret)
  result = xxh3_64bits_withSeed(state.buf, state.seed)

proc digest128*(state: Xxh3State): Xxh128 =
  if state.kind != xxh3_128:
    raise newException(ValueError, "XXH3 state holds a 64-bit hash")
  if state.useSecret:
    if state.buf.len <= Xxh3MidsizeMax:
      # Short inputs use the seed alone (default secret), like withSeed.
      return xxh3_128bits_withSeed(state.buf, state.seed)
    return xxh3_128_withSecret(state.buf, state.secret)
  result = xxh3_128bits_withSeed(state.buf, state.seed)

{.pop.}
