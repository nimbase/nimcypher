# SHA-512/256 hash and HMAC-SHA-512/256.
#
# Per FIPS 180-4 §5.3.6: same compression as SHA-512 with a different IV,
# output truncated to 32 bytes. HMAC per FIPS 198-1 with 128-byte blocks.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512

{.push checks: off.}

const
  Sha512_256DigestSize* = 32
  Sha512_256BlockSize* = 128

type
  Sha512_256Digest* = array[Sha512_256DigestSize, byte]
  Sha512_256Hmac* = array[Sha512_256DigestSize, byte]
  Sha512_256Context* = Sha512Context
  Sha512_256HmacContext* = object
    key: array[128, byte]
    ctx: Sha512Context

proc init512_256*(ctx: var Sha512Context) =
  ctx.hash[0] = 0x22312194fc2bf72c'u64
  ctx.hash[1] = 0x9f555fa3c84c64c2'u64
  ctx.hash[2] = 0x2393b86b6f53b151'u64
  ctx.hash[3] = 0x963877195940eabd'u64
  ctx.hash[4] = 0x96283ee2a88effe3'u64
  ctx.hash[5] = 0xbe5e1e2553863992'u64
  ctx.hash[6] = 0x2b0199fc2c85b8aa'u64
  ctx.hash[7] = 0x0eb72ddc81c52ca2'u64
  ctx.inputSize[0] = 0
  ctx.inputSize[1] = 0
  ctx.inputIdx = 0
  ctx.input = default(array[16, uint64])

proc sha512_256*(message: openArray[byte]): Sha512_256Digest =
  ## Compute the SHA-512/256 hash of `message`.
  var ctx: Sha512Context
  init512_256(ctx)
  update(ctx, message)
  let full = final(ctx)
  for i in 0 ..< Sha512_256DigestSize:
    result[i] = full[i]

proc initHmac512_256*(ctx: var Sha512_256HmacContext, key: openArray[byte]) =
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 128:
    var hashed = sha512_256(key)
    for i in 0 ..< Sha512_256DigestSize:
      ctx.key[i] = hashed[i]
    wipe(hashed)
    keyPtr = cast[BytePtr](unsafeAddr ctx.key[0])
    keySize = Sha512_256DigestSize
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 128:
    ctx.key[i] = 0x36
  init512_256(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha512_256HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha512_256HmacContext): Sha512_256Hmac =
  let innerFull = final(ctx.ctx)
  var inner: Sha512_256Digest
  for i in 0 ..< Sha512_256DigestSize:
    inner[i] = innerFull[i]
  for i in 0 ..< 128:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init512_256(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  let outerFull = final(ctx.ctx)
  for i in 0 ..< Sha512_256DigestSize:
    result[i] = outerFull[i]
  wipe(ctx)

proc sha512_256Hmac*(key, message: openArray[byte]): Sha512_256Hmac =
  ## Compute an HMAC-SHA-512/256 of `message`.
  var ctx: Sha512_256HmacContext
  initHmac512_256(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
