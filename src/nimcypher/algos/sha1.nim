# SHA-1 hash and HMAC-SHA-1 — pure Nim, no C dependency.
#
# SHA-1 per FIPS 180-4 §6.1, HMAC per RFC 2104. Reference: RFC 3174.
# SHA-1 is collision-broken: do not use it for collision-dependent
# purposes (signatures, certificates, content addressing). HMAC-SHA-1
# is retained for legacy interop (notably RSA-OAEP-SHA1 / JWA RSA-OAEP).
# Structure mirrors `sha256.nim`: streaming `Sha1Context`,
# `Sha1HmacContext` with `init/update/final`, one-shot `sha1/sha1Hmac`.
#
# Dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

const
  Sha1BlockSize* = 64
  Sha1DigestSize* = 20

type
  Sha1Digest* = array[Sha1DigestSize, byte]

  Sha1Context* = object
    h: array[5, uint32]
    buf: array[64, byte]
    bufLen: int
    totalLen: uint64

  Sha1HmacContext* = object
    key: array[64, byte]
    ctx: Sha1Context

proc rotl32(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

proc load32Be(s: BytePtr): uint32 {.inline.} =
  (uint32(s[0]) shl 24) or (uint32(s[1]) shl 16) or
    (uint32(s[2]) shl 8) or uint32(s[3])

proc store32Be(outp: BytePtr, v: uint32) {.inline.} =
  outp[0] = byte(v shr 24)
  outp[1] = byte(v shr 16)
  outp[2] = byte(v shr 8)
  outp[3] = byte(v)

# SHA-1 compression: 80 rounds, 512-bit block in W[0..15] BE.
proc sha1Compress(h: var array[5, uint32], blk: BytePtr) {.inline.} =
  var w: array[80, uint32]
  for i in 0 ..< 16:
    w[i] = load32Be(blk + i * 4)
  for i in 16 ..< 80:
    w[i] = rotl32(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

  var a = h[0]
  var b = h[1]
  var c = h[2]
  var d = h[3]
  var e = h[4]

  for i in 0 ..< 80:
    var f, k: uint32
    if i < 20:
      f = (b and c) or ((not b) and d)
      k = 0x5A827999'u32
    elif i < 40:
      f = b xor c xor d
      k = 0x6ED9EBA1'u32
    elif i < 60:
      f = (b and c) or (b and d) or (c and d)
      k = 0x8F1BBCDC'u32
    else:
      f = b xor c xor d
      k = 0xCA62C1D6'u32
    let temp = rotl32(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = temp

  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
  h[4] += e

proc init*(ctx: var Sha1Context) =
  ctx.h[0] = 0x67452301'u32
  ctx.h[1] = 0xEFCDAB89'u32
  ctx.h[2] = 0x98BADCFE'u32
  ctx.h[3] = 0x10325476'u32
  ctx.h[4] = 0xC3D2E1F0'u32
  ctx.buf = default(array[64, byte])
  ctx.bufLen = 0
  ctx.totalLen = 0

proc update*(ctx: var Sha1Context, message: openArray[byte]) =
  if message.len == 0:
    return
  var off = 0
  var left = message.len
  # fill pending buffer to a full block
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
      sha1Compress(ctx.h, cast[BytePtr](addr ctx.buf[0]))
      ctx.bufLen = 0
  # direct block path
  while left >= 64:
    sha1Compress(ctx.h,
      cast[BytePtr](unsafeAddr message[off]))
    off += 64
    left -= 64
    ctx.totalLen += 64
  # tail
  if left > 0:
    for i in 0 ..< left:
      ctx.buf[i] = message[off + i]
    ctx.bufLen = left
    ctx.totalLen += uint64(left)

proc final*(ctx: var Sha1Context): Sha1Digest =
  let bitLen = ctx.totalLen * 8
  # pad: 0x80 then zeros until length field fits (need 9 bytes: 1 + 8)
  var padLen = 1
  while (ctx.bufLen + padLen) mod 64 != 56:
    inc padLen
  var pad = newSeq[byte](padLen + 8)
  pad[0] = 0x80
  let o = padLen
  pad[o+0] = byte(bitLen shr 56)
  pad[o+1] = byte(bitLen shr 48)
  pad[o+2] = byte(bitLen shr 40)
  pad[o+3] = byte(bitLen shr 32)
  pad[o+4] = byte(bitLen shr 24)
  pad[o+5] = byte(bitLen shr 16)
  pad[o+6] = byte(bitLen shr 8)
  pad[o+7] = byte(bitLen)
  update(ctx, pad)
  wipe(pad)
  # ctx.bufLen must be 0 and totalLen a multiple of 64 now
  for i in 0 ..< 5:
    store32Be(cast[BytePtr](addr result[i * 4]), ctx.h[i])
  wipe(ctx)

proc sha1*(message: openArray[byte]): Sha1Digest =
  ## Compute the SHA-1 hash of `message` (FIPS 180-4).
  ## Collision-broken: legacy interop only, do not use in new designs.
  var ctx: Sha1Context
  init(ctx)
  update(ctx, message)
  result = final(ctx)

# HMAC-SHA-1 (streaming, mirrors sha256.nim)

proc initHmac*(ctx: var Sha1HmacContext, key: openArray[byte]) =
  ## Initialize an HMAC-SHA-1 context with the given key.
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 64:
    var hashed = sha1(key)
    for i in 0 ..< Sha1DigestSize:
      ctx.key[i] = hashed[i]
    wipe(hashed)
    keyPtr = cast[BytePtr](addr ctx.key[0])
    keySize = Sha1DigestSize
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 64:
    ctx.key[i] = 0x36
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha1HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha1HmacContext): Sha1Digest =
  ## Compute the 20-byte HMAC.
  var inner: Sha1Digest = final(ctx.ctx)
  for i in 0 ..< 64:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  result = final(ctx.ctx)
  wipe(inner)
  wipe(ctx)

proc sha1Hmac*(key, message: openArray[byte]): Sha1Digest =
  ## Compute HMAC-SHA-1 of `message` under `key` (RFC 2104).
  var ctx: Sha1HmacContext
  initHmac(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
