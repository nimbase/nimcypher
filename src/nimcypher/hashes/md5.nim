# MD5 message digest and HMAC-MD5: pure Nim, no C dependency.
#
# MD5 per RFC 1321 (Rivest, 1992), HMAC per RFC 2104. Structure mirrors
# `algos/sha1.nim` and `algos/sha256.nim`: streaming `Md5Context` and
# `Md5HmacContext` with `init/update/final`, one-shot `md5/md5Hmac`.
#
# WARNING: MD5 is cryptographically broken (collisions are practical).
# Provided for interop with legacy formats (checksums, HMAC-MD5 in old
# protocols); do not use in new designs.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../algos/common

{.push checks: off.}

const
  Md5BlockSize* = 64
  Md5DigestSize* = 16

type
  Md5Digest* = array[Md5DigestSize, byte]

  Md5Context* = object
    h: array[4, uint32]
    buf: array[64, byte]
    bufLen: int
    totalLen: uint64

  Md5HmacContext* = object
    key: array[64, byte]
    ctx: Md5Context

# T table: floor(2^32 * abs(sin(i))), i = 1..64 (RFC 1321 Appendix A).
const Md5T: array[64, uint32] = [
  0xd76aa478'u32, 0xe8c7b756'u32, 0x242070db'u32, 0xc1bdceee'u32,
  0xf57c0faf'u32, 0x4787c62a'u32, 0xa8304613'u32, 0xfd469501'u32,
  0x698098d8'u32, 0x8b44f7af'u32, 0xffff5bb1'u32, 0x895cd7be'u32,
  0x6b901122'u32, 0xfd987193'u32, 0xa679438e'u32, 0x49b40821'u32,
  0xf61e2562'u32, 0xc040b340'u32, 0x265e5a51'u32, 0xe9b6c7aa'u32,
  0xd62f105d'u32, 0x02441453'u32, 0xd8a1e681'u32, 0xe7d3fbc8'u32,
  0x21e1cde6'u32, 0xc33707d6'u32, 0xf4d50d87'u32, 0x455a14ed'u32,
  0xa9e3e905'u32, 0xfcefa3f8'u32, 0x676f02d9'u32, 0x8d2a4c8a'u32,
  0xfffa3942'u32, 0x8771f681'u32, 0x6d9d6122'u32, 0xfde5380c'u32,
  0xa4beea44'u32, 0x4bdecfa9'u32, 0xf6bb4b60'u32, 0xbebfbc70'u32,
  0x289b7ec6'u32, 0xeaa127fa'u32, 0xd4ef3085'u32, 0x04881d05'u32,
  0xd9d4d039'u32, 0xe6db99e5'u32, 0x1fa27cf8'u32, 0xc4ac5665'u32,
  0xf4292244'u32, 0x432aff97'u32, 0xab9423a7'u32, 0xfc93a039'u32,
  0x655b59c3'u32, 0x8f0ccc92'u32, 0xffeff47d'u32, 0x85845dd1'u32,
  0x6fa87e4f'u32, 0xfe2ce6e0'u32, 0xa3014314'u32, 0x4e0811a1'u32,
  0xf7537e82'u32, 0xbd3af235'u32, 0x2ad7d2bb'u32, 0xeb86d391'u32,
]

const
  Md5S1: array[4, int] = [7, 12, 17, 22]
  Md5S2: array[4, int] = [5, 9, 14, 20]
  Md5S3: array[4, int] = [4, 11, 16, 23]
  Md5S4: array[4, int] = [6, 10, 15, 21]
  # Target register per step: A, D, C, B (RFC [ABCD]/[DABC]/[CDAB]/[BCDA]).
  Md5Order: array[4, int] = [0, 3, 2, 1]

proc rotl32(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

proc md5F(x, y, z: uint32): uint32 {.inline.} =
  (x and y) or ((not x) and z)

proc md5G(x, y, z: uint32): uint32 {.inline.} =
  (x and z) or (y and (not z))

proc md5H(x, y, z: uint32): uint32 {.inline.} =
  x xor y xor z

proc md5I(x, y, z: uint32): uint32 {.inline.} =
  y xor (x or (not z))

proc md5Compress(h: var array[4, uint32], blk: BytePtr) {.inline.} =
  var x: array[16, uint32]
  for i in 0 ..< 16:
    x[i] = load32Le(blk + i * 4)
  var v = h
  for j in 0 ..< 64:
    let r = j shr 4
    var k, s: int
    let t = Md5Order[j and 3]
    let bIdx = Md5Order[(j + 3) and 3]
    let f0 = v[(t + 1) and 3]
    let f1 = v[(t + 2) and 3]
    let f2 = v[(t + 3) and 3]
    var f: uint32
    case r
    of 0:
      k = j
      s = Md5S1[j and 3]
      f = md5F(f0, f1, f2)
    of 1:
      k = (1 + 5 * j) and 15
      s = Md5S2[j and 3]
      f = md5G(f0, f1, f2)
    of 2:
      k = (5 + 3 * j) and 15
      s = Md5S3[j and 3]
      f = md5H(f0, f1, f2)
    else:
      k = (7 * j) and 15
      s = Md5S4[j and 3]
      f = md5I(f0, f1, f2)
    v[t] = v[bIdx] + rotl32(v[t] + f + x[k] + Md5T[j], s)
  for i in 0 ..< 4:
    h[i] += v[i]

proc init*(ctx: var Md5Context) =
  ctx.h[0] = 0x67452301'u32
  ctx.h[1] = 0xefcdab89'u32
  ctx.h[2] = 0x98badcfe'u32
  ctx.h[3] = 0x10325476'u32
  ctx.buf = default(array[64, byte])
  ctx.bufLen = 0
  ctx.totalLen = 0

proc update*(ctx: var Md5Context, message: openArray[byte]) =
  if message.len == 0:
    return
  var off = 0
  var left = message.len
  if ctx.bufLen > 0:
    let need = 64 - ctx.bufLen
    let take = min(need, left)
    for i in 0 ..< take:
      ctx.buf[ctx.bufLen + i] = message[off + i]
    ctx.bufLen += take
    off += take
    left -= take
    ctx.totalLen += uint64(take)
    if ctx.bufLen == 64:
      md5Compress(ctx.h, cast[BytePtr](addr ctx.buf[0]))
      ctx.bufLen = 0
  while left >= 64:
    md5Compress(ctx.h, cast[BytePtr](unsafeAddr message[off]))
    off += 64
    left -= 64
    ctx.totalLen += 64
  if left > 0:
    for i in 0 ..< left:
      ctx.buf[i] = message[off + i]
    ctx.bufLen = left
    ctx.totalLen += uint64(left)

proc final*(ctx: var Md5Context): Md5Digest =
  let bitLen = ctx.totalLen * 8
  var padLen = 1
  while (ctx.bufLen + padLen) mod 64 != 56:
    inc padLen
  var pad = newSeq[byte](padLen + 8)
  pad[0] = 0x80
  let o = padLen
  pad[o+0] = byte(bitLen)
  pad[o+1] = byte(bitLen shr 8)
  pad[o+2] = byte(bitLen shr 16)
  pad[o+3] = byte(bitLen shr 24)
  pad[o+4] = byte(bitLen shr 32)
  pad[o+5] = byte(bitLen shr 40)
  pad[o+6] = byte(bitLen shr 48)
  pad[o+7] = byte(bitLen shr 56)
  update(ctx, pad)
  wipe(pad)
  for i in 0 ..< 4:
    store32Le(cast[BytePtr](addr result[i * 4]), ctx.h[i])
  wipe(ctx)

proc md5*(message: openArray[byte]): Md5Digest =
  ## Compute the MD5 digest of `message` (RFC 1321). Broken: legacy use only.
  var ctx: Md5Context
  init(ctx)
  update(ctx, message)
  result = final(ctx)

# HMAC-MD5 (streaming, mirrors algos/sha256.nim).

proc initHmac*(ctx: var Md5HmacContext, key: openArray[byte]) =
  ## Initialize an HMAC-MD5 context with the given key.
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 64:
    let hashed = md5(key)
    for i in 0 ..< 16:
      ctx.key[i] = hashed[i]
    keyPtr = cast[BytePtr](addr ctx.key[0])
    keySize = 16
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 64:
    ctx.key[i] = 0x36
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Md5HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Md5HmacContext): Md5Digest =
  ## Compute the 16-byte HMAC.
  var inner: Md5Digest = final(ctx.ctx)
  for i in 0 ..< 64:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  result = final(ctx.ctx)
  wipe(inner)
  wipe(ctx)

proc md5Hmac*(key, message: openArray[byte]): Md5Digest =
  ## Compute an HMAC-MD5 of `message` (RFC 2104). Legacy use only.
  var ctx: Md5HmacContext
  initHmac(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
