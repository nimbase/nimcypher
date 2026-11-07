# SHA-512/224 hash and HMAC-SHA-512/224.
#
# Per FIPS 180-4 §5.3.5: same compression as SHA-512 with a different IV,
# output truncated to 28 bytes. HMAC per FIPS 198-1 with 128-byte blocks.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512

{.push checks: off.}

const
  Sha512_224DigestSize* = 28
  Sha512_224BlockSize* = 128

type
  Sha512_224Digest* = array[Sha512_224DigestSize, byte]
  Sha512_224Hmac* = array[Sha512_224DigestSize, byte]
  Sha512_224Context* = Sha512Context
  Sha512_224HmacContext* = object
    key: array[128, byte]
    ctx: Sha512Context

proc init512_224*(ctx: var Sha512Context) =
  ctx.hash[0] = 0x8c3d37c819544da2'u64
  ctx.hash[1] = 0x73e1996689dcd4d6'u64
  ctx.hash[2] = 0x1dfab7ae32ff9c82'u64
  ctx.hash[3] = 0x679dd514582f9fcf'u64
  ctx.hash[4] = 0x0f6d2b697bd44da8'u64
  ctx.hash[5] = 0x77e36f7304c48942'u64
  ctx.hash[6] = 0x3f9d85a86a1d36c8'u64
  ctx.hash[7] = 0x1112e6ad91d692a1'u64
  ctx.inputSize[0] = 0
  ctx.inputSize[1] = 0
  ctx.inputIdx = 0
  ctx.input = default(array[16, uint64])

proc sha512_224*(message: openArray[byte]): Sha512_224Digest =
  ## Compute the SHA-512/224 hash of `message`.
  var ctx: Sha512Context
  init512_224(ctx)
  update(ctx, message)
  let full = final(ctx)
  for i in 0 ..< Sha512_224DigestSize:
    result[i] = full[i]

proc initHmac512_224*(ctx: var Sha512_224HmacContext, key: openArray[byte]) =
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 128:
    var hashed = sha512_224(key)
    for i in 0 ..< Sha512_224DigestSize:
      ctx.key[i] = hashed[i]
    wipe(hashed)
    keyPtr = cast[BytePtr](unsafeAddr ctx.key[0])
    keySize = Sha512_224DigestSize
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 128:
    ctx.key[i] = 0x36
  init512_224(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha512_224HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha512_224HmacContext): Sha512_224Hmac =
  let innerFull = final(ctx.ctx)
  var inner: Sha512_224Digest
  for i in 0 ..< Sha512_224DigestSize:
    inner[i] = innerFull[i]
  for i in 0 ..< 128:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init512_224(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  let outerFull = final(ctx.ctx)
  for i in 0 ..< Sha512_224DigestSize:
    result[i] = outerFull[i]
  wipe(ctx)

proc sha512_224Hmac*(key, message: openArray[byte]): Sha512_224Hmac =
  ## Compute an HMAC-SHA-512/224 of `message`.
  var ctx: Sha512_224HmacContext
  initHmac512_224(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
