# SHA-224 hash and HMAC-SHA-224.
#
# Per FIPS 180-4: same compression as SHA-256 with a different IV,
# output truncated to 28 bytes. HMAC per RFC 2104 / RFC 4231 with
# 64-byte blocks.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha256

{.push checks: off.}

const
  Sha224DigestSize* = 28
  Sha224BlockSize* = 64

type
  Sha224Digest* = array[Sha224DigestSize, byte]
  Sha224Hmac* = array[Sha224DigestSize, byte]
  Sha224Context* = Sha256Context
  Sha224HmacContext* = object
    key: array[64, byte]
    ctx: Sha256Context

proc init224*(ctx: var Sha256Context) =
  ctx.h[0] = 0xc1059ed8'u32
  ctx.h[1] = 0x367cd507'u32
  ctx.h[2] = 0x3070dd17'u32
  ctx.h[3] = 0xf70e5939'u32
  ctx.h[4] = 0xffc00b31'u32
  ctx.h[5] = 0x68581511'u32
  ctx.h[6] = 0x64f98fa7'u32
  ctx.h[7] = 0xbefa4fa4'u32
  ctx.buf = default(array[64, byte])
  ctx.bufLen = 0
  ctx.totalLen = 0

proc sha224*(message: openArray[byte]): Sha224Digest =
  ## Compute the SHA-224 hash of `message`.
  var ctx: Sha256Context
  init224(ctx)
  update(ctx, message)
  let full = final(ctx)
  for i in 0 ..< Sha224DigestSize:
    result[i] = full[i]

proc initHmac224*(ctx: var Sha224HmacContext, key: openArray[byte]) =
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 64:
    var hashed = sha224(key)
    for i in 0 ..< Sha224DigestSize:
      ctx.key[i] = hashed[i]
    wipe(hashed)
    keyPtr = cast[BytePtr](unsafeAddr ctx.key[0])
    keySize = Sha224DigestSize
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 64:
    ctx.key[i] = 0x36
  init224(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha224HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha224HmacContext): Sha224Hmac =
  let innerFull = final(ctx.ctx)
  var inner: Sha224Digest
  for i in 0 ..< Sha224DigestSize:
    inner[i] = innerFull[i]
  for i in 0 ..< 64:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init224(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  let outerFull = final(ctx.ctx)
  for i in 0 ..< Sha224DigestSize:
    result[i] = outerFull[i]
  wipe(ctx)

proc sha224Hmac*(key, message: openArray[byte]): Sha224Hmac =
  ## Compute an HMAC-SHA-224 of `message`.
  var ctx: Sha224HmacContext
  initHmac224(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
