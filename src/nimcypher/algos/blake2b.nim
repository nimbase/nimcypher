# BLAKE2b cryptographic hash.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
  import ./internal/blake2b_simd

{.push checks: off.}

type
  Blake2bContext* = object
    hash*: array[8, uint64]
    inputOffset*: array[2, uint64]
    input*: array[16, uint64]
    inputIdx*: int
    hashSize*: int

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
  var v8 = blake2bIv[0]; var v9 = blake2bIv[1]
  var v10 = blake2bIv[2]; var v11 = blake2bIv[3]
  var v12 = blake2bIv[4] xor ctx.inputOffset[0]
  var v13 = blake2bIv[5] xor ctx.inputOffset[1]
  var v14 = blake2bIv[6] xor (not (uint64(isLastBlock) - 1))
  var v15 = blake2bIv[7]

  # mangle work vector (unrolled: same as C's BLAKE2_ROUND(0..11))
  template blake2Round(r: static int) =
    g(v0, v4, v8, v12, ctx.input[blake2bSigma[r][0]], ctx.input[blake2bSigma[r][1]])
    g(v1, v5, v9, v13, ctx.input[blake2bSigma[r][2]], ctx.input[blake2bSigma[r][3]])
    g(v2, v6, v10, v14, ctx.input[blake2bSigma[r][4]], ctx.input[blake2bSigma[r][5]])
    g(v3, v7, v11, v15, ctx.input[blake2bSigma[r][6]], ctx.input[blake2bSigma[r][7]])
    g(v0, v5, v10, v15, ctx.input[blake2bSigma[r][8]], ctx.input[blake2bSigma[r][9]])
    g(v1, v6, v11, v12, ctx.input[blake2bSigma[r][10]], ctx.input[blake2bSigma[r][11]])
    g(v2, v7, v8, v13, ctx.input[blake2bSigma[r][12]], ctx.input[blake2bSigma[r][13]])
    g(v3, v4, v9, v14, ctx.input[blake2bSigma[r][14]], ctx.input[blake2bSigma[r][15]])

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
    ctx.hash[i] = blake2bIv[i]
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

when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
  proc blake2bParallel*[T](messages: array[4, T],
                        hashSize: int = 64): array[4, seq[byte]] =
    ## Hash four messages with BLAKE2b in parallel using SIMD. Equivalent to
    ## calling `blake2b` on each message; matching 128-byte blocks of the
    ## four messages are compressed together (one SIMD lane each). Messages
    ## shorter than 128 bytes, and the trailing block of each message, are
    ## finished with the scalar compressor.
    var ctxs: array[4, Blake2bContext]
    for k in 0 ..< 4:
      init(ctxs[k], hashSize)
    var offsets = [0, 0, 0, 0]
    while true:
      var nActive = 0
      for k in 0 ..< 4:
        if messages[k].len - offsets[k] > 128:
          inc nActive
      if nActive < 2:
        break
      var laneMask = 0'u64
      var hashes: array[4, array[8, uint64]]
      var offs: array[4, array[2, uint64]]
      var blocks: array[4, array[16, uint64]]
      for k in 0 ..< 4:
        if messages[k].len - offsets[k] > 128:
          laneMask = laneMask or (1'u64 shl k)
          for j in 0 ..< 8:
            hashes[k][j] = ctxs[k].hash[j]
          # the offset fed to the compressor includes this block (the scalar
          # `compress` adds the block length before XORing it into v12/v13)
          offs[k][0] = ctxs[k].inputOffset[0] + 128
          offs[k][1] = ctxs[k].inputOffset[1] +
                       (if offs[k][0] < 128: 1'u64 else: 0'u64)
          load64LeBuf(blocks[k].toOpenArray(0, 15),
                      cast[BytePtr](unsafeAddr messages[k][offsets[k]]), 16)
          offsets[k] += 128
      compress4(hashes, offs, blocks, laneMask)
      for k in 0 ..< 4:
        if (laneMask and (1'u64 shl k)) != 0:
          ctxs[k].hash = hashes[k]
          ctxs[k].inputOffset = offs[k]
    for k in 0 ..< 4:
      let left = messages[k].len - offsets[k]
      if left > 0:
        update(ctxs[k], messages[k].toOpenArray(offsets[k], messages[k].len - 1))
      result[k] = final(ctxs[k])

{.pop.}
