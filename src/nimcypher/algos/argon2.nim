# Argon2 password hashing and key derivation.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./blake2b

{.push checks: off.}

type
  Argon2Algorithm* = enum
    d = 0
    i = 1
    id = 2

  Argon2Config* = object
    algorithm*: Argon2Algorithm
    nbBlocks*: uint32  # memory hardness, >= 8 * nbLanes
    nbPasses*: uint32  # CPU hardness, >= 1
    nbLanes*: uint32   # parallelism level (single threaded anyway)

  Blk = object
    a: array[128, uint64]

proc blakeUpdate32(ctx: var Blake2bContext, input: uint32) {.inline.} =
  var buf: array[4, byte]
  store32Le(cast[BytePtr](unsafeAddr buf[0]), input)
  update(ctx, buf)
  wipe(buf)

proc blakeUpdatePtr(ctx: var Blake2bContext, p: BytePtr, size: int) =
  if size > 0:
    var tmp = newSeq[byte](size)
    for i in 0 ..< size:
      tmp[i] = p[i]
    update(ctx, tmp)
    wipe(tmp)

proc blakeUpdate32Buf(ctx: var Blake2bContext, p: BytePtr, size: uint32) =
  blakeUpdate32(ctx, size)
  blakeUpdatePtr(ctx, p, int(size))

proc copyBlock(o: var Blk, inp: Blk) {.inline.} =
  for i in 0 ..< 128:
    o.a[i] = inp.a[i]

proc xorBlock(o: var Blk, inp: Blk) {.inline.} =
  for i in 0 ..< 128:
    o.a[i] = o.a[i] xor inp.a[i]

# Hash with a virtually unlimited digest size.
proc extendedHash(digest: BytePtr, digestSize: uint32,
                  input: BytePtr, inputSize: uint32) =
  var ctx: Blake2bContext
  init(ctx, int(min(digestSize, 64)))
  blakeUpdate32(ctx, digestSize)
  blakeUpdatePtr(ctx, input, int(inputSize))
  let first = final(ctx)
  for i in 0 ..< int(min(digestSize, 64)):
    digest[i] = first[i]
  if digestSize > 64:
    # the conversion to u64 avoids integer overflow on
    # ludicrously big hash sizes.
    let r = uint32((uint64(digestSize) + 31) shr 5) - 2
    var counter = 1'u32
    var inputOffset = 0'u32
    var outputOffset = 32'u32
    while counter < r:
      # input and output overlap. This is intentional.
      var ctx2: Blake2bContext
      init(ctx2, 64)
      blakeUpdatePtr(ctx2, digest + int(inputOffset), 64)
      let h = final(ctx2)
      for i in 0 ..< 64:
        digest[int(outputOffset) + i] = h[i]
      counter += 1
      inputOffset += 32
      outputOffset += 32
    var ctx3: Blake2bContext
    init(ctx3, int(digestSize - (32 * r)))
    blakeUpdatePtr(ctx3, digest + int(inputOffset), 64)
    let h2 = final(ctx3)
    for i in 0 ..< int(digestSize - (32 * r)):
      digest[int(outputOffset) + i] = h2[i]

template lsb(x: untyped): untyped = uint64(uint32(x))

template g(a, b, c, d: untyped) =
  a += b + ((lsb(a) * lsb(b)) shl 1)
  d = d xor a
  d = rotr64(d, 32)
  c += d + ((lsb(c) * lsb(d)) shl 1)
  b = b xor c
  b = rotr64(b, 24)
  a += b + ((lsb(a) * lsb(b)) shl 1)
  d = d xor a
  d = rotr64(d, 16)
  c += d + ((lsb(c) * lsb(d)) shl 1)
  b = b xor c
  b = rotr64(b, 63)

template round(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13,
               v14, v15: untyped) =
  g(v0, v4, v8, v12)
  g(v1, v5, v9, v13)
  g(v2, v6, v10, v14)
  g(v3, v7, v11, v15)
  g(v0, v5, v10, v15)
  g(v1, v6, v11, v12)
  g(v2, v7, v8, v13)
  g(v3, v4, v9, v14)

# Core of the compression function G. Computes Z from R in place.
proc gRounds(b: var Blk) {.inline.} =
  # column rounds (work_block = Q)
  var i = 0
  while i < 128:
    round(b.a[i], b.a[i + 1], b.a[i + 2], b.a[i + 3],
          b.a[i + 4], b.a[i + 5], b.a[i + 6], b.a[i + 7],
          b.a[i + 8], b.a[i + 9], b.a[i + 10], b.a[i + 11],
          b.a[i + 12], b.a[i + 13], b.a[i + 14], b.a[i + 15])
    i += 16
  # row rounds (b = Z)
  i = 0
  while i < 16:
    round(b.a[i], b.a[i + 1], b.a[i + 16], b.a[i + 17],
          b.a[i + 32], b.a[i + 33], b.a[i + 48], b.a[i + 49],
          b.a[i + 64], b.a[i + 65], b.a[i + 80], b.a[i + 81],
          b.a[i + 96], b.a[i + 97], b.a[i + 112], b.a[i + 113])
    i += 2

proc argon2Impl(hash: BytePtr, hashSize: uint32, workArea: BytePtr,
                config: Argon2Config,
                pass: BytePtr, passSize: uint32,
                salt: BytePtr, saltSize: uint32,
                key: BytePtr, keySize: uint32,
                ad: BytePtr, adSize: uint32) =
  let segmentSize = config.nbBlocks div config.nbLanes div 4
  let laneSize = segmentSize * 4
  let nbBlocks = laneSize * config.nbLanes # rounding down
  let blocks = cast[ptr UncheckedArray[Blk]](workArea)

  block:
    var initialHash: array[72, byte] # 64 bytes plus 2 words for future hashes
    var ctx: Blake2bContext
    init(ctx, 64)
    blakeUpdate32(ctx, config.nbLanes) # p: number of "threads"
    blakeUpdate32(ctx, hashSize)
    blakeUpdate32(ctx, config.nbBlocks)
    blakeUpdate32(ctx, config.nbPasses)
    blakeUpdate32(ctx, 0x13'u32)      # v: version number
    blakeUpdate32(ctx, uint32(config.algorithm)) # y: Argon2i, Argon2d...
    blakeUpdate32Buf(ctx, pass, passSize)
    blakeUpdate32Buf(ctx, salt, saltSize)
    blakeUpdate32Buf(ctx, key, keySize)
    blakeUpdate32Buf(ctx, ad, adSize)
    let fin = final(ctx)
    for i in 0 ..< 64:
      initialHash[i] = fin[i]

    # fill first 2 blocks of each lane
    var hashArea: array[1024, byte]
    var lane: uint32 = 0
    while lane < config.nbLanes:
      var i = 0'u32
      while i < 2:
        store32Le(cast[BytePtr](unsafeAddr initialHash[64]), i)
        store32Le(cast[BytePtr](unsafeAddr initialHash[68]), lane)
        extendedHash(cast[BytePtr](unsafeAddr hashArea[0]), 1024,
                     cast[BytePtr](unsafeAddr initialHash[0]), 72)
        load64LeBuf(blocks[int(lane * laneSize + i)].a.toOpenArray(0, 127),
                    cast[BytePtr](unsafeAddr hashArea[0]), 128)
        i += 1
      lane += 1
    wipe(initialHash)
    wipe(hashArea)

  # Argon2i and Argon2id start with constant time indexing
  var constantTime = config.algorithm != Argon2Algorithm.d

  # Fill (and re-fill) the rest of the blocks
  var tmp: Blk
  var passIndex: uint32 = 0
  while passIndex < config.nbPasses:
    var slice: uint32 = 0
    while slice < 4:
      # on the first slice of the first pass, blocks 0 and 1 are already
      # filled, hence pass_offset.
      let passOffset = if passIndex == 0 and slice == 0: 2'u32 else: 0'u32
      let sliceOffset = slice * segmentSize

      # Argon2id switches back to non-constant time indexing
      # after the first two slices of the first pass
      if slice == 2 and config.algorithm == Argon2Algorithm.id:
        constantTime = false

      var segment: uint32 = 0
      while segment < config.nbLanes:
        var indexBlock: Blk
        var indexCtr: uint32 = 1
        var blockIndex: uint32 = passOffset
        while blockIndex < segmentSize:
          # current and previous blocks
          let laneOffset = segment * laneSize
          let currentIdx = int(laneOffset + sliceOffset + blockIndex)
          let previousIdx =
            if blockIndex == 0 and sliceOffset == 0:
              int(laneOffset + laneSize - 1)
            else:
              int(laneOffset + sliceOffset + blockIndex - 1)
          let current = addr blocks[currentIdx]
          let previous = addr blocks[previousIdx]

          var indexSeed: uint64
          if constantTime:
            if blockIndex == passOffset or (blockIndex mod 128) == 0:
              # fill or refresh deterministic indices block
              for i in 0 ..< 128:
                indexBlock.a[i] = 0
              indexBlock.a[0] = uint64(passIndex)
              indexBlock.a[1] = uint64(segment)
              indexBlock.a[2] = uint64(slice)
              indexBlock.a[3] = uint64(nbBlocks)
              indexBlock.a[4] = uint64(config.nbPasses)
              indexBlock.a[5] = uint64(config.algorithm)
              indexBlock.a[6] = uint64(indexCtr)
              indexCtr += 1
              # ... then shuffle it
              copyBlock(tmp, indexBlock)
              gRounds(indexBlock)
              xorBlock(indexBlock, tmp)
              copyBlock(tmp, indexBlock)
              gRounds(indexBlock)
              xorBlock(indexBlock, tmp)
            indexSeed = indexBlock.a[int(blockIndex mod 128)]
          else:
            indexSeed = previous.a[0]

          # establish the reference set
          let nextSlice = ((slice + 1) mod 4) * segmentSize
          let windowStart = if passIndex == 0: 0'u32 else: nextSlice
          let nbSegments = if passIndex == 0: slice else: 3'u32
          let lane =
            if passIndex == 0 and slice == 0:
              segment
            else:
              uint32(indexSeed shr 32) mod config.nbLanes
          let windowSize =
            nbSegments * segmentSize +
            (if lane == segment: blockIndex - 1
             elif blockIndex == 0: uint32(-1)
             else: 0'u32)

          # find reference block
          let j1 = indexSeed and 0xffffffff'u64 # block selector
          let x = (j1 * j1) shr 32
          let y = (uint64(windowSize) * x) shr 32
          let z = uint64(windowSize - 1'u32) - y
          let refIdx = uint32((uint64(windowStart) + z) mod uint64(laneSize))
          let index = lane * laneSize + refIdx
          let reference = addr blocks[int(index)]

          # shuffle the previous & reference block into the current block
          copyBlock(tmp, previous[])
          xorBlock(tmp, reference[])
          if passIndex == 0:
            copyBlock(current[], tmp)
          else:
            xorBlock(current[], tmp)
          gRounds(tmp)
          xorBlock(current[], tmp)
          blockIndex += 1
        segment += 1
      slice += 1
    passIndex += 1

  # wipe temporary block
  wipe(tmp)

  # XOR last blocks of each lane
  var lastBlockIdx = int(laneSize - 1)
  var laneN: uint32 = 1
  while laneN < config.nbLanes:
    let nextBlockIdx = lastBlockIdx + int(laneSize)
    xorBlock(blocks[nextBlockIdx], blocks[lastBlockIdx])
    lastBlockIdx = nextBlockIdx
    laneN += 1

  # serialize last block
  var finalBlock: array[1024, byte]
  store64LeBuf(cast[BytePtr](unsafeAddr finalBlock[0]),
               blocks[lastBlockIdx].a, 128)

  # wipe work area
  var w = cast[BytePtr](workArea)
  for i in 0 ..< int(128 * nbBlocks):
    w[i] = 0

  # hash the very last block with H' into the output hash
  extendedHash(hash, hashSize, cast[BytePtr](unsafeAddr finalBlock[0]), 1024)
  wipe(finalBlock)

proc argon2Impl(config: Argon2Config, hashSize: int, password, salt,
                key, ad: openArray[byte]): seq[byte] =
  ## Password key derivation with Argon2 (d, i or id).
  let nbBlocks = int(config.nbBlocks)
  var workArea = newSeq[byte](nbBlocks * 1024)
  var pass = if password.len > 0: cast[BytePtr](unsafeAddr password[0]) else: nil
  var saltp = if salt.len > 0: cast[BytePtr](unsafeAddr salt[0]) else: nil
  var keyp = if key.len > 0: cast[BytePtr](unsafeAddr key[0]) else: nil
  var adp = if ad.len > 0: cast[BytePtr](unsafeAddr ad[0]) else: nil
  result = newSeqUninit[byte](hashSize)
  argon2Impl(cast[BytePtr](unsafeAddr result[0]), uint32(hashSize),
             cast[BytePtr](unsafeAddr workArea[0]), config,
             pass, uint32(password.len),
             saltp, uint32(salt.len),
             keyp, uint32(key.len),
             adp, uint32(ad.len))
  wipe(workArea)

proc argon2*(config: Argon2Config, hashSize: int, password, salt: openArray[byte]):
    seq[byte] =
  ## Password key derivation with Argon2 (d, i or id), no extra key or
  ## associated data.
  result = argon2Impl(config, hashSize, password, salt, @[], @[])

proc argon2*(config: Argon2Config, hashSize: int, password, salt, key,
             ad: openArray[byte]): seq[byte] =
  ## Password key derivation with Argon2 (d, i or id), with an optional
  ## key and associated data.
  result = argon2Impl(config, hashSize, password, salt, key, ad)

{.pop.}
