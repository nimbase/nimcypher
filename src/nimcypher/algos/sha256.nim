# SHA-256 hash and HMAC-SHA-256.
#
# Pure Nim per FIPS 180-4 §6.2, HMAC per RFC 2104 / RFC 5869 (via hkdf.nim).
# Structure mirrors `sha512.nim`: streaming `Sha256Context`,
# `Sha256HmacContext` with `init/update/final`, one-shot `sha256/sha256Hmac`.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

const
  Sha256BlockSize* = 64
  Sha256DigestSize* = 32

type
  Sha256Digest* = array[Sha256DigestSize, byte]

  Sha256Context* = object
    h: array[8, uint32]
    buf: array[64, byte]
    bufLen: int
    totalLen: uint64

  Sha256HmacContext* = object
    key: array[64, byte]
    ctx: Sha256Context

const
  K256: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32,
  ]

proc rotr(x: uint32, n: int): uint32 {.inline.} =
  (x shr n) or (x shl (32 - n))

proc load32Be(s: BytePtr): uint32 {.inline.} =
  (uint32(s[0]) shl 24) or (uint32(s[1]) shl 16) or
    (uint32(s[2]) shl 8) or uint32(s[3])

proc store32Be(outp: BytePtr, v: uint32) {.inline.} =
  outp[0] = byte(v shr 24)
  outp[1] = byte(v shr 16)
  outp[2] = byte(v shr 8)
  outp[3] = byte(v)

proc sha256Compress(h: var array[8, uint32], blk: BytePtr) {.inline.} =
  var w: array[64, uint32]
  for i in 0 ..< 16:
    w[i] = load32Be(blk + i * 4)
  for i in 16 ..< 64:
    let s0 = rotr(w[i-15], 7) xor rotr(w[i-15], 18) xor (w[i-15] shr 3)
    let s1 = rotr(w[i-2], 17) xor rotr(w[i-2], 19) xor (w[i-2] shr 10)
    w[i] = w[i-16] + s0 + w[i-7] + s1

  var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
  var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]
  for i in 0 ..< 64:
    let s1 = rotr(e, 6) xor rotr(e, 11) xor rotr(e, 25)
    let ch = (e and f) xor ((not e) and g)
    let t1 = hh + s1 + ch + K256[i] + w[i]
    let s0 = rotr(a, 2) xor rotr(a, 13) xor rotr(a, 22)
    let maj = (a and b) xor (a and c) xor (b and c)
    let t2 = s0 + maj
    hh = g; g = f; f = e; e = d + t1
    d = c; c = b; b = a; a = t1 + t2

  h[0] += a; h[1] += b; h[2] += c; h[3] += d
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh

proc init*(ctx: var Sha256Context) =
  ctx.h[0] = 0x6a09e667'u32
  ctx.h[1] = 0xbb67ae85'u32
  ctx.h[2] = 0x3c6ef372'u32
  ctx.h[3] = 0xa54ff53a'u32
  ctx.h[4] = 0x510e527f'u32
  ctx.h[5] = 0x9b05688c'u32
  ctx.h[6] = 0x1f83d9ab'u32
  ctx.h[7] = 0x5be0cd19'u32
  ctx.buf = default(array[64, byte])
  ctx.bufLen = 0
  ctx.totalLen = 0

proc update*(ctx: var Sha256Context, message: openArray[byte]) =
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
      sha256Compress(ctx.h, cast[BytePtr](addr ctx.buf[0]))
      ctx.bufLen = 0
  # direct block path
  while left >= 64:
    sha256Compress(ctx.h,
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

proc final*(ctx: var Sha256Context): array[32, byte] =
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
  for i in 0 ..< 8:
    store32Be(cast[BytePtr](addr result[i * 4]), ctx.h[i])
  wipe(ctx)

proc sha256*(message: openArray[byte]): array[32, byte] =
  ## Compute the SHA-256 hash of `message`.
  var ctx: Sha256Context
  init(ctx)
  update(ctx, message)
  result = final(ctx)

# HMAC-SHA-256 (streaming, mirrors sha512.nim)

proc initHmac*(ctx: var Sha256HmacContext, key: openArray[byte]) =
  ## Initialize an HMAC-SHA-256 context with the given key.
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 64:
    let hashed = sha256(key)
    for i in 0 ..< 32:
      ctx.key[i] = hashed[i]
    keyPtr = cast[BytePtr](addr ctx.key[0])
    keySize = 32
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 64:
    ctx.key[i] = 0x36
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha256HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha256HmacContext): array[32, byte] =
  ## Compute the 32-byte HMAC.
  var inner: array[32, byte] = final(ctx.ctx)
  for i in 0 ..< 64:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  result = final(ctx.ctx)
  wipe(inner)
  wipe(ctx)

proc sha256Hmac*(key, message: openArray[byte]): array[32, byte] =
  ## Compute an HMAC-SHA-256 of `message`.
  var ctx: Sha256HmacContext
  initHmac(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
