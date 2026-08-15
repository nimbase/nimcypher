# BLAKE2b cryptographic hash.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

type
  Blake2bContext* = object
    hash*: array[8, uint64]
    inputOffset*: array[2, uint64]
    input*: array[16, uint64]
    inputIdx*: int
    hashSize*: int

const
  iv: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
    0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
    0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64,
  ]

const
  sigma: array[12, array[16, uint8]] = [
    [0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14'u8, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11'u8, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7'u8, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9'u8, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2'u8, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12'u8, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13'u8, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6'u8, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10'u8, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14'u8, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  ]

template g(a, b, c, d, x, y: untyped) =
  a += b + x
  d = rotr64(d xor a, 32)
  c += d
  b = rotr64(b xor c, 24)
  a += b + y
  d = rotr64(d xor a, 16)
  c += d
  b = rotr64(b xor c, 63)

proc compress(ctx: var Blake2bContext, isLastBlock: int) =
  # increment input offset
  let y = ctx.inputIdx
  ctx.inputOffset[0] += uint64(y)
  if ctx.inputOffset[0] < uint64(y):
    ctx.inputOffset[1] += 1

  # init work vector
  var v0 = ctx.hash[0]; var v1 = ctx.hash[1]
  var v2 = ctx.hash[2]; var v3 = ctx.hash[3]
  var v4 = ctx.hash[4]; var v5 = ctx.hash[5]
  var v6 = ctx.hash[6]; var v7 = ctx.hash[7]
  var v8 = iv[0]; var v9 = iv[1]
  var v10 = iv[2]; var v11 = iv[3]
  var v12 = iv[4] xor ctx.inputOffset[0]
  var v13 = iv[5] xor ctx.inputOffset[1]
  var v14 = iv[6] xor (not (uint64(isLastBlock) - 1))
  var v15 = iv[7]

  # mangle work vector (unrolled: same as C's BLAKE2_ROUND(0..11))
  template blake2Round(r: static int) =
    g(v0, v4, v8, v12, ctx.input[sigma[r][0]], ctx.input[sigma[r][1]])
    g(v1, v5, v9, v13, ctx.input[sigma[r][2]], ctx.input[sigma[r][3]])
    g(v2, v6, v10, v14, ctx.input[sigma[r][4]], ctx.input[sigma[r][5]])
    g(v3, v7, v11, v15, ctx.input[sigma[r][6]], ctx.input[sigma[r][7]])
    g(v0, v5, v10, v15, ctx.input[sigma[r][8]], ctx.input[sigma[r][9]])
    g(v1, v6, v11, v12, ctx.input[sigma[r][10]], ctx.input[sigma[r][11]])
    g(v2, v7, v8, v13, ctx.input[sigma[r][12]], ctx.input[sigma[r][13]])
    g(v3, v4, v9, v14, ctx.input[sigma[r][14]], ctx.input[sigma[r][15]])

  blake2Round(0)
  blake2Round(1)
  blake2Round(2)
  blake2Round(3)
  blake2Round(4)
  blake2Round(5)
  blake2Round(6)
  blake2Round(7)
  blake2Round(8)
  blake2Round(9)
  blake2Round(10)
  blake2Round(11)

  # update hash
  ctx.hash[0] = ctx.hash[0] xor v0 xor v8
  ctx.hash[1] = ctx.hash[1] xor v1 xor v9
  ctx.hash[2] = ctx.hash[2] xor v2 xor v10
  ctx.hash[3] = ctx.hash[3] xor v3 xor v11
  ctx.hash[4] = ctx.hash[4] xor v4 xor v12
  ctx.hash[5] = ctx.hash[5] xor v5 xor v13
  ctx.hash[6] = ctx.hash[6] xor v6 xor v14
  ctx.hash[7] = ctx.hash[7] xor v7 xor v15

proc init*(ctx: var Blake2bContext, hashSize: int, key: openArray[byte] = []) =
  ## Initialize a BLAKE2b context. Optionally keyed for MAC usage.
  for i in 0 ..< 8:
    ctx.hash[i] = iv[i]
  ctx.hash[0] = ctx.hash[0] xor uint64(0x01010000) xor
                (uint64(key.len) shl 8) xor uint64(hashSize)
  ctx.inputOffset[0] = 0
  ctx.inputOffset[1] = 0
  ctx.hashSize = hashSize
  ctx.inputIdx = 0
  ctx.input = default(array[16, uint64])

  # if there is a key, the first block is that key (padded with zeroes)
  if key.len > 0:
    var keyBlock: array[128, byte]
    for i in 0 ..< key.len:
      keyBlock[i] = key[i]
    load64LeBuf(ctx.input.toOpenArray(0, 15),
                cast[BytePtr](unsafeAddr keyBlock[0]), 16)
    ctx.inputIdx = 128
    wipe(keyBlock)

proc initBlake2b*(hashSize: int = 64): Blake2bContext =
  init(result, hashSize)

proc initBlake2b*(key: openArray[byte], hashSize: int = 64): Blake2bContext =
  init(result, hashSize, key)

proc update*(ctx: var Blake2bContext, message: openArray[byte]) =
  if message.len == 0:
    return
  var msg = cast[BytePtr](unsafeAddr message[0])
  var msgSize = message.len

  # align with word boundaries
  if (ctx.inputIdx and 7) != 0:
    let nbBytes = min(gap(ctx.inputIdx, 8), msgSize)
    let word = ctx.inputIdx shr 3
    let byte = ctx.inputIdx and 7
    for i in 0 ..< nbBytes:
      ctx.input[word] = ctx.input[word] or
                        (uint64(msg[i]) shl ((byte + i) shl 3))
    ctx.inputIdx += nbBytes
    msg = msg + nbBytes
    msgSize -= nbBytes

  # align with block boundaries
  if (ctx.inputIdx and 127) != 0:
    let nbWords = min(gap(ctx.inputIdx, 128), msgSize) shr 3
    load64LeBuf(ctx.input.toOpenArray(ctx.inputIdx shr 3,
                                      ctx.inputIdx shr 3 + nbWords - 1),
                msg, nbWords)
    ctx.inputIdx += nbWords shl 3
    msg = msg + (nbWords shl 3)
    msgSize -= nbWords shl 3

  # process block by block
  let nbBlocks = msgSize shr 7
  for i in 0 ..< nbBlocks:
    if ctx.inputIdx == 128:
      compress(ctx, 0)
    load64LeBuf(ctx.input.toOpenArray(0, 15), msg, 16)
    msg = msg + 128
    ctx.inputIdx = 128
  msgSize = msgSize and 127

  if msgSize != 0:
    # compress block & flush input buffer as needed
    if ctx.inputIdx == 128:
      compress(ctx, 0)
      ctx.inputIdx = 0
    if ctx.inputIdx == 0:
      ctx.input = default(array[16, uint64])
    # fill remaining words
    let nbWords = msgSize shr 3
    load64LeBuf(ctx.input.toOpenArray(0, nbWords - 1), msg, nbWords)
    ctx.inputIdx += nbWords shl 3
    msg = msg + (nbWords shl 3)
    msgSize -= nbWords shl 3
    # fill remaining bytes
    for i in 0 ..< msgSize:
      let word = ctx.inputIdx shr 3
      let byte = ctx.inputIdx and 7
      ctx.input[word] = ctx.input[word] or
                        (uint64(msg[i]) shl (byte shl 3))
      ctx.inputIdx += 1

proc final*(ctx: var Blake2bContext): seq[byte] =
  compress(ctx, 1) # compress the last block
  let hashSize = min(ctx.hashSize, 64)
  let nbWords = hashSize shr 3
  result = newSeqUninit[byte](hashSize)
  for i in 0 ..< nbWords:
    store64Le(cast[BytePtr](unsafeAddr result[i * 8]), ctx.hash[i])
  for i in (nbWords shl 3) ..< hashSize:
    result[i] = byte((ctx.hash[i shr 3] shr (8 * (i and 7))) and 0xff)
  wipe(ctx)

proc blake2b*(message: openArray[byte], hashSize: int = 64): seq[byte] =
  ## Compute the BLAKE2b hash of `message`.
  var ctx: Blake2bContext
  init(ctx, hashSize)
  update(ctx, message)
  result = final(ctx)

proc keyedBlake2b*(message, key: openArray[byte], hashSize: int = 64): seq[byte] =
  ## Compute a keyed BLAKE2b MAC of `message`.
  var ctx: Blake2bContext
  init(ctx, hashSize, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
