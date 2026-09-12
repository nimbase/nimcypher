# SHA-384 hash and HMAC-SHA-384.
#
# Per FIPS 180-4: same compression as SHA-512 with a different IV,
# output truncated to 48 bytes. HMAC per RFC 2104 with 128-byte blocks.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512

{.push checks: off.}

const
  Sha384DigestSize* = 48
  Sha384BlockSize* = 128

type
  Sha384Digest* = array[Sha384DigestSize, byte]
  Sha384Hmac* = array[Sha384DigestSize, byte]
  Sha384Context* = Sha512Context
  Sha384HmacContext* = object
    key: array[128, byte]
    ctx: Sha512Context

proc init384*(ctx: var Sha512Context) =
  ctx.hash[0] = 0xcbbb9d5dc1059ed8'u64
  ctx.hash[1] = 0x629a292a367cd507'u64
  ctx.hash[2] = 0x9159015a3070dd17'u64
  ctx.hash[3] = 0x152fecd8f70e5939'u64
  ctx.hash[4] = 0x67332667ffc00b31'u64
  ctx.hash[5] = 0x8eb44a8768581511'u64
  ctx.hash[6] = 0xdb0c2e0d64f98fa7'u64
  ctx.hash[7] = 0x47b5481dbefa4fa4'u64
  ctx.inputSize[0] = 0
  ctx.inputSize[1] = 0
  ctx.inputIdx = 0
  ctx.input = default(array[16, uint64])

proc sha384*(message: openArray[byte]): Sha384Digest =
  ## Compute the SHA-384 hash of `message`.
  var ctx: Sha512Context
  init384(ctx)
  update(ctx, message)
  let full = final(ctx)
  for i in 0 ..< Sha384DigestSize:
    result[i] = full[i]

proc initHmac384*(ctx: var Sha384HmacContext, key: openArray[byte]) =
  var keyPtr: BytePtr = nil
  var keySize = key.len
  if keySize > 128:
    let hashed = sha384(key)
    for i in 0 ..< Sha384DigestSize:
      ctx.key[i] = hashed[i]
    keyPtr = cast[BytePtr](unsafeAddr ctx.key[0])
    keySize = Sha384DigestSize
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 128:
    ctx.key[i] = 0x36
  init384(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha384HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha384HmacContext): Sha384Hmac =
  let innerFull = final(ctx.ctx)
  var inner: Sha384Digest
  for i in 0 ..< Sha384DigestSize:
    inner[i] = innerFull[i]
  for i in 0 ..< 128:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  init384(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, inner)
  let outerFull = final(ctx.ctx)
  for i in 0 ..< Sha384DigestSize:
    result[i] = outerFull[i]
  wipe(ctx)

proc sha384Hmac*(key, message: openArray[byte]): Sha384Hmac =
  ## Compute an HMAC-SHA-384 of `message`.
  var ctx: Sha384HmacContext
  initHmac384(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
