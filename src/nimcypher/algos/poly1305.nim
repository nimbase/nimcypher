# Poly1305 one-time authenticator.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

type
  Poly1305Context* = object
    c*: array[16, byte]   # chunk of the message
    cIdx*: int            # how many bytes are there in the chunk
    r*: array[4, uint32]  # constant multiplier (from the secret key)
    pad*: array[4, uint32]
    h*: array[5, uint32]  # accumulated hash

# h = (h + c) * r
proc polyBlocks(ctx: var Poly1305Context, inp: BytePtr, nbBlocks: int,
                endFlag: uint32) {.inline.} =
  let r0 = ctx.r[0]
  let r1 = ctx.r[1]
  let r2 = ctx.r[2]
  let r3 = ctx.r[3]
  let rr0 = (r0 shr 2) * 5          # lose 2 bits...
  let rr1 = (r1 shr 2) + r1         # rr1 == (r1 >> 2) * 5
  let rr2 = (r2 shr 2) + r2         # rr2 == (r2 >> 2) * 5
  let rr3 = (r3 shr 2) + r3         # rr3 == (r3 >> 2) * 5
  let rr4 = r0 and 3                # ...recover 2 bits
  var h0 = ctx.h[0]
  var h1 = ctx.h[1]
  var h2 = ctx.h[2]
  var h3 = ctx.h[3]
  var h4 = ctx.h[4]

  var inptr = inp
  for i in 0 ..< nbBlocks:
    # h + c, without carry propagation
    let s0 = uint64(h0) + uint64(load32Le(inptr)); inptr = inptr + 4
    let s1 = uint64(h1) + uint64(load32Le(inptr)); inptr = inptr + 4
    let s2 = uint64(h2) + uint64(load32Le(inptr)); inptr = inptr + 4
    let s3 = uint64(h3) + uint64(load32Le(inptr)); inptr = inptr + 4
    let s4 = h4 + endFlag

    # (h + c) * r, without carry propagation
    let x0 = s0 * uint64(r0) + s1 * uint64(rr3) + s2 * uint64(rr2) +
             s3 * uint64(rr1) + uint64(s4) * uint64(rr0)
    let x1 = s0 * uint64(r1) + s1 * uint64(r0) + s2 * uint64(rr3) +
             s3 * uint64(rr2) + uint64(s4) * uint64(rr1)
    let x2 = s0 * uint64(r2) + s1 * uint64(r1) + s2 * uint64(r0) +
             s3 * uint64(rr3) + uint64(s4) * uint64(rr2)
    let x3 = s0 * uint64(r3) + s1 * uint64(r2) + s2 * uint64(r1) +
             s3 * uint64(r0) + uint64(s4) * uint64(rr3)
    let x4 = s4 * rr4

    # partial reduction modulo 2^130 - 5
    let u5 = uint32(x3 shr 32) + x4                        # u5 <= 7ffffff5
    let u0 = uint64(uint32(u5 shr 2) * 5) + (x0 and 0xffffffff'u64)
    let u1 = uint64(uint32(u0 shr 32)) + (x1 and 0xffffffff'u64) + (x0 shr 32)
    let u2 = uint64(uint32(u1 shr 32)) + (x2 and 0xffffffff'u64) + (x1 shr 32)
    let u3 = uint64(uint32(u2 shr 32)) + (x3 and 0xffffffff'u64) + (x2 shr 32)
    let u4 = uint32(u3 shr 32) + (u5 and 3)                # u4 <= 4

    # Update the hash
    h0 = uint32(u0)
    h1 = uint32(u1)
    h2 = uint32(u2)
    h3 = uint32(u3)
    h4 = u4
  ctx.h[0] = h0
  ctx.h[1] = h1
  ctx.h[2] = h2
  ctx.h[3] = h3
  ctx.h[4] = h4

proc initPoly1305*(ctx: var Poly1305Context, key: array[32, byte]) =
  ## Initialize a Poly1305 context with the given key.
  ctx.h = default(array[5, uint32]) # initial hash is zero
  ctx.cIdx = 0
  # load r and pad (r has some of its bits cleared)
  load32LeBuf(ctx.r.toOpenArray(0, 3), cast[BytePtr](unsafeAddr key[0]), 4)
  load32LeBuf(ctx.pad.toOpenArray(0, 3), cast[BytePtr](unsafeAddr key[16]), 4)
  for i in 0 ..< 1:
    ctx.r[i] = ctx.r[i] and 0x0fffffff'u32
  for i in 1 ..< 4:
    ctx.r[i] = ctx.r[i] and 0x0ffffffc'u32

proc update*(ctx: var Poly1305Context, message: openArray[byte]) =
  ## Feed a message chunk into the authenticator.
  if message.len == 0:
    return
  var msg = cast[BytePtr](unsafeAddr message[0])
  var msgSize = message.len

  # align ourselves with block boundaries
  let aligned = min(gap(ctx.cIdx, 16), msgSize)
  for i in 0 ..< aligned:
    ctx.c[ctx.cIdx] = msg[i]
    ctx.cIdx += 1
  msg = msg + aligned
  msgSize -= aligned

  # if block is complete, process it
  if ctx.cIdx == 16:
    polyBlocks(ctx, cast[BytePtr](unsafeAddr ctx.c[0]), 1, 1)
    ctx.cIdx = 0

  # process the message block by block
  let nbBlocks = msgSize shr 4
  polyBlocks(ctx, msg, nbBlocks, 1)
  msg = msg + (nbBlocks shl 4)
  msgSize = msgSize and 15

  # remaining bytes (we never complete a block here)
  for i in 0 ..< msgSize:
    ctx.c[ctx.cIdx] = msg[i]
    ctx.cIdx += 1

proc final*(ctx: var Poly1305Context): array[16, byte] =
  ## Compute the 16-byte MAC.
  # process the last block (if any)
  if ctx.cIdx != 0:
    for i in ctx.cIdx ..< 16:
      ctx.c[i] = 0
    ctx.c[ctx.cIdx] = 1
    polyBlocks(ctx, cast[BytePtr](unsafeAddr ctx.c[0]), 1, 0)

  # check if we should subtract 2^130-5 by performing the
  # corresponding carry propagation.
  var c: uint64 = 5
  for i in 0 ..< 4:
    c += uint64(ctx.h[i])
    c = c shr 32
  c += uint64(ctx.h[4])
  c = (c shr 2) * 5 # shift the carry back to the beginning
  # c now indicates how many times we should subtract 2^130-5 (0 or 1)
  for i in 0 ..< 4:
    c += uint64(ctx.h[i]) + uint64(ctx.pad[i])
    store32Le(cast[BytePtr](unsafeAddr result[i * 4]), uint32(c))
    c = c shr 32
  wipe(ctx)

proc poly1305*(message: openArray[byte], key: array[32, byte]): array[16, byte] =
  ## Compute a one-time Poly1305 authenticator of `message`.
  var ctx: Poly1305Context
  initPoly1305(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
