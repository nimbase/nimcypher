# ChaCha20 stream cipher.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
  import ./internal/chacha20_simd
  when defined(amd64):
    # The AVX2 two-block kernel requires AVX2 on x86_64. The SIMD build is
    # opt-in, so the whole binary is built for AVX2 in that case.
    {.passC: "-mavx2".}

{.push checks: off.}

const chacha20Constant = [byte 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
                          0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b]

template quarterRound(a, b, c, d: untyped) =
  a += b
  d = rotl32(d xor a, 16)
  c += d
  b = rotl32(b xor c, 12)
  a += b
  d = rotl32(d xor a, 8)
  c += d
  b = rotl32(b xor c, 7)

proc chacha20RoundsScalar*(outp: var array[16, uint32], inp: array[16, uint32]) {.inline.} =
  ## Reference scalar ChaCha20 rounds (20 rounds, 2 per loop iteration).
  ## The SIMD feature makes `chacha20Rounds` use `simdRounds`; this scalar
  ## kernel stays available for verification and benchmarking.
  var t0 = inp[0]; var t1 = inp[1]; var t2 = inp[2]; var t3 = inp[3]
  var t4 = inp[4]; var t5 = inp[5]; var t6 = inp[6]; var t7 = inp[7]
  var t8 = inp[8]; var t9 = inp[9]; var t10 = inp[10]; var t11 = inp[11]
  var t12 = inp[12]; var t13 = inp[13]; var t14 = inp[14]; var t15 = inp[15]
  for i in 0 ..< 10: # 20 rounds, 2 rounds per loop
    quarterRound(t0, t4, t8, t12)  # column 0
    quarterRound(t1, t5, t9, t13)  # column 1
    quarterRound(t2, t6, t10, t14) # column 2
    quarterRound(t3, t7, t11, t15) # column 3
    quarterRound(t0, t5, t10, t15) # diagonal 0
    quarterRound(t1, t6, t11, t12) # diagonal 1
    quarterRound(t2, t7, t8, t13)  # diagonal 2
    quarterRound(t3, t4, t9, t14)  # diagonal 3
  outp[0] = t0; outp[1] = t1; outp[2] = t2; outp[3] = t3
  outp[4] = t4; outp[5] = t5; outp[6] = t6; outp[7] = t7
  outp[8] = t8; outp[9] = t9; outp[10] = t10; outp[11] = t11
  outp[12] = t12; outp[13] = t13; outp[14] = t14; outp[15] = t15

proc chacha20Rounds*(outp: var array[16, uint32], inp: array[16, uint32]) {.inline.} =
  ## 20 rounds of ChaCha20. Uses the SIMD kernel when built with
  ## `features.nimcypher.nimsimd`, otherwise the scalar kernel.
  when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
    simdRounds(outp, inp)
  else:
    chacha20RoundsScalar(outp, inp)

proc chacha20H*(outp: BytePtr, key: array[32, byte], inp: array[16, byte]) =
  var blockBuf: array[16, uint32]
  load32LeBuf(blockBuf, cast[BytePtr](unsafeAddr chacha20Constant[0]), 4)
  load32LeBuf(blockBuf.toOpenArray(4, 11),
              cast[BytePtr](unsafeAddr key[0]), 8)
  load32LeBuf(blockBuf.toOpenArray(12, 15),
              cast[BytePtr](unsafeAddr inp[0]), 4)
  chacha20Rounds(blockBuf, blockBuf)
  # prevent reversal of the rounds by revealing only half of the buffer.
  store32LeBuf(outp, blockBuf.toOpenArray(0, 3), 4)
  store32LeBuf(outp + 16, blockBuf.toOpenArray(12, 15), 4)
  wipe(blockBuf)

proc chacha20HScalar*(outp: BytePtr, key: array[32, byte], inp: array[16, byte]) =
  ## Scalar reference HChaCha20 (never SIMD-accelerated).
  var blockBuf: array[16, uint32]
  load32LeBuf(blockBuf, cast[BytePtr](unsafeAddr chacha20Constant[0]), 4)
  load32LeBuf(blockBuf.toOpenArray(4, 11),
              cast[BytePtr](unsafeAddr key[0]), 8)
  load32LeBuf(blockBuf.toOpenArray(12, 15),
              cast[BytePtr](unsafeAddr inp[0]), 4)
  chacha20RoundsScalar(blockBuf, blockBuf)
  store32LeBuf(outp, blockBuf.toOpenArray(0, 3), 4)
  store32LeBuf(outp + 16, blockBuf.toOpenArray(12, 15), 4)
  wipe(blockBuf)

template chacha20BuildInput(outp: var array[16, uint32], key: array[32, byte],
                            nonce: array[8, byte], ctr: uint64) =
  load32LeBuf(outp.toOpenArray(0, 3), cast[BytePtr](unsafeAddr chacha20Constant[0]), 4)
  load32LeBuf(outp.toOpenArray(4, 11), cast[BytePtr](unsafeAddr key[0]), 8)
  load32LeBuf(outp.toOpenArray(14, 15), cast[BytePtr](unsafeAddr nonce[0]), 2)
  outp[12] = uint32(ctr)
  outp[13] = uint32(ctr shr 32)

when defined(features.nimcypher.nimsimd) and defined(amd64):
  proc chacha20DjbAvx2(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                       key: array[32, byte], nonce: array[8, byte],
                       ctr: uint64): uint64 =
    ## ChaCha20-DJB using the AVX2 two-block kernel (amd64 SIMD builds only).
    ## `din` holds two interleaved blocks (see `simdRounds2`).
    var din: array[32, uint32]
    for i in 0 ..< 4: # row 0: constants
      let c = load32Le(cast[BytePtr](unsafeAddr chacha20Constant[i * 4]))
      din[i] = c
      din[4 + i] = c
    for i in 0 ..< 4: # row 1: key words 4..7
      let k = load32Le(cast[BytePtr](unsafeAddr key[i * 4]))
      din[8 + i] = k
      din[12 + i] = k
    for i in 0 ..< 4: # row 2: key words 8..11
      let k = load32Le(cast[BytePtr](unsafeAddr key[(4 + i) * 4]))
      din[16 + i] = k
      din[20 + i] = k
    # row 3: counter words 12..13 (per pair), nonce words 14..15
    din[26] = load32Le(cast[BytePtr](unsafeAddr nonce[0]))
    din[27] = load32Le(cast[BytePtr](unsafeAddr nonce[4]))
    din[30] = load32Le(cast[BytePtr](unsafeAddr nonce[0]))
    din[31] = load32Le(cast[BytePtr](unsafeAddr nonce[4]))
  
    var pool: array[32, uint32]
    var textSize2 = textSize
    var ct = cipherText
    var pt = plainText
    let nbBlocks = textSize2 shr 6
    let nbPairs = nbBlocks shr 1
    var c = ctr
    for _ in 0 ..< nbPairs:
      din[24] = uint32(c)
      din[25] = uint32(c shr 32)
      din[28] = uint32(c + 1)
      din[29] = uint32((c + 1) shr 32)
      simdRounds2(pool, din)
      if pt != nil:
        for w in 0 ..< 16:
          let aIdx = (w shr 2) shl 3 + (w and 3)
          let bIdx = aIdx + 4
          let off = w shl 2
          store32Le(ct + off, (pool[aIdx] + din[aIdx]) xor load32Le(pt + off))
          store32Le(ct + 64 + off, (pool[bIdx] + din[bIdx]) xor load32Le(pt + 64 + off))
      else:
        for w in 0 ..< 16:
          let aIdx = (w shr 2) shl 3 + (w and 3)
          let bIdx = aIdx + 4
          let off = w shl 2
          store32Le(ct + off, pool[aIdx] + din[aIdx])
          store32Le(ct + 64 + off, pool[bIdx] + din[bIdx])
      ct = ct + 128
      if pt != nil:
        pt = pt + 128
      c = c + 2
  
    # Odd block
    if (nbBlocks and 1) == 1:
      var inputBuf: array[16, uint32]
      chacha20BuildInput(inputBuf, key, nonce, c)
      var pool1: array[16, uint32]
      chacha20Rounds(pool1, inputBuf)
      if pt != nil:
        for j in 0 ..< 16:
          store32Le(ct, (pool1[j] + inputBuf[j]) xor load32Le(pt))
          ct = ct + 4
          pt = pt + 4
      else:
        for j in 0 ..< 16:
          store32Le(ct, pool1[j] + inputBuf[j])
          ct = ct + 4
      c = c + 1
  
    textSize2 = textSize2 and 63
    # Last (incomplete) block
    if textSize2 > 0:
      var inputBuf: array[16, uint32]
      chacha20BuildInput(inputBuf, key, nonce, c)
      var pool1: array[16, uint32]
      chacha20Rounds(pool1, inputBuf)
      var tmp: array[64, byte]
      for i in 0 ..< 16:
        store32Le(cast[BytePtr](unsafeAddr tmp[i * 4]), pool1[i] + inputBuf[i])
      if pt == nil:
        for i in 0 ..< textSize2:
          ct[i] = tmp[i]
      else:
        for i in 0 ..< textSize2:
          ct[i] = tmp[i] xor pt[i]
      wipe(tmp)
    result = c + (if textSize2 > 0: 1'u64 else: 0'u64)
    wipe(pool)
    wipe(din)

proc chacha20Djb*(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                  key: array[32, byte], nonce: array[8, byte],
                  ctr: uint64): uint64 =
  when defined(features.nimcypher.nimsimd) and defined(amd64):
    chacha20DjbAvx2(cipherText, plainText, textSize, key, nonce, ctr)
  else:
    var inputBuf: array[16, uint32]
    chacha20BuildInput(inputBuf, key, nonce, ctr)

    # Whole blocks
    var pool: array[16, uint32]
    var textSize2 = textSize
    var ct = cipherText
    var pt = plainText
    let nbBlocks = textSize2 shr 6
    for i in 0 ..< nbBlocks:
      chacha20Rounds(pool, inputBuf)
      if pt != nil:
        for j in 0 ..< 16:
          let p = pool[j] + inputBuf[j]
          store32Le(ct, p xor load32Le(pt))
          ct = ct + 4
          pt = pt + 4
      else:
        for j in 0 ..< 16:
          let p = pool[j] + inputBuf[j]
          store32Le(ct, p)
          ct = ct + 4
      inputBuf[12] += 1
      if inputBuf[12] == 0:
        inputBuf[13] += 1
    textSize2 = textSize2 and 63

    # Last (incomplete) block
    if textSize2 > 0:
      chacha20Rounds(pool, inputBuf)
      var tmp: array[64, byte]
      for i in 0 ..< 16:
        store32Le(cast[BytePtr](unsafeAddr tmp[i * 4]), pool[i] + inputBuf[i])
      if pt == nil:
        for i in 0 ..< textSize2:
          ct[i] = tmp[i]
      else:
        for i in 0 ..< textSize2:
          ct[i] = tmp[i] xor pt[i]
      wipe(tmp)
    result = inputBuf[12] + (uint64(inputBuf[13]) shl 32) +
             (if textSize2 > 0: 1'u64 else: 0'u64)

    wipe(pool)
    wipe(inputBuf)

proc chacha20DjbScalar*(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                        key: array[32, byte], nonce: array[8, byte],
                        ctr: uint64): uint64 =
  ## Scalar reference ChaCha20-DJB (never SIMD-accelerated).
  var inputBuf: array[16, uint32]
  load32LeBuf(inputBuf, cast[BytePtr](unsafeAddr chacha20Constant[0]), 4)
  load32LeBuf(inputBuf.toOpenArray(4, 11),
              cast[BytePtr](unsafeAddr key[0]), 8)
  load32LeBuf(inputBuf.toOpenArray(14, 15),
              cast[BytePtr](unsafeAddr nonce[0]), 2)
  inputBuf[12] = uint32(ctr)
  inputBuf[13] = uint32(ctr shr 32)

  var pool: array[16, uint32]
  var textSize2 = textSize
  var ct = cipherText
  var pt = plainText
  let nbBlocks = textSize2 shr 6
  for i in 0 ..< nbBlocks:
    chacha20RoundsScalar(pool, inputBuf)
    if pt != nil:
      for j in 0 ..< 16:
        let p = pool[j] + inputBuf[j]
        store32Le(ct, p xor load32Le(pt))
        ct = ct + 4
        pt = pt + 4
    else:
      for j in 0 ..< 16:
        let p = pool[j] + inputBuf[j]
        store32Le(ct, p)
        ct = ct + 4
    inputBuf[12] += 1
    if inputBuf[12] == 0:
      inputBuf[13] += 1
  textSize2 = textSize2 and 63

  if textSize2 > 0:
    chacha20RoundsScalar(pool, inputBuf)
    var tmp: array[64, byte]
    for i in 0 ..< 16:
      store32Le(cast[BytePtr](unsafeAddr tmp[i * 4]), pool[i] + inputBuf[i])
    if pt == nil:
      for i in 0 ..< textSize2:
        ct[i] = tmp[i]
    else:
      for i in 0 ..< textSize2:
        ct[i] = tmp[i] xor pt[i]
    wipe(tmp)
  result = inputBuf[12] + (uint64(inputBuf[13]) shl 32) +
           (if textSize2 > 0: 1'u64 else: 0'u64)

  wipe(pool)
  wipe(inputBuf)

proc chacha20Ietf*(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                   key: array[32, byte], nonce: array[12, byte],
                   ctr: uint32): uint32 =
  let bigCtr = uint64(ctr) + (uint64(load32Le(cast[BytePtr](unsafeAddr nonce[0]))) shl 32)
  var nonce8: array[8, byte]
  for i in 0 ..< 8:
    nonce8[i] = nonce[i + 4]
  result = uint32(chacha20Djb(cipherText, plainText, textSize, key,
                              nonce8, bigCtr))

proc chacha20X*(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                key: array[32, byte], nonce: array[24, byte],
                ctr: uint64): uint64 =
  var subKey: array[32, byte]
  var nonce16: array[16, byte]
  for i in 0 ..< 16:
    nonce16[i] = nonce[i]
  chacha20H(cast[BytePtr](unsafeAddr subKey[0]), key, nonce16)
  var nonce8: array[8, byte]
  for i in 0 ..< 8:
    nonce8[i] = nonce[i + 16]
  result = chacha20Djb(cipherText, plainText, textSize, subKey, nonce8, ctr)
  wipe(subKey)

# Convenience public API
proc chacha20*(data: openArray[byte], key: array[32, byte],
               nonce: array[8, byte], counter: uint64 = 0): seq[byte] =
  ## Encrypt/decrypt data with ChaCha20 (DJB variant, 64-bit counter,
  ## 64-bit nonce). Encryption and decryption are the same operation.
  result = newSeqUninit[byte](data.len)
  var dp = if data.len > 0: cast[BytePtr](unsafeAddr data[0]) else: nil
  var rp = if result.len > 0: cast[BytePtr](unsafeAddr result[0]) else: nil
  discard chacha20Djb(rp, dp, data.len, key, nonce, counter)

proc chacha20Ietf*(data: openArray[byte], key: array[32, byte],
                   nonce: array[12, byte], counter: uint32 = 0): seq[byte] =
  ## Encrypt/decrypt data with the IETF variant of ChaCha20 (32-bit
  ## counter, 96-bit nonce).
  result = newSeqUninit[byte](data.len)
  var dp = if data.len > 0: cast[BytePtr](unsafeAddr data[0]) else: nil
  var rp = if result.len > 0: cast[BytePtr](unsafeAddr result[0]) else: nil
  discard chacha20Ietf(rp, dp, data.len, key, nonce, counter)

proc chacha20X*(data: openArray[byte], key: array[32, byte],
                nonce: array[24, byte], counter: uint64 = 0): seq[byte] =
  ## Encrypt/decrypt data with XChaCha20 (64-bit counter, 192-bit nonce).
  result = newSeqUninit[byte](data.len)
  var dp = if data.len > 0: cast[BytePtr](unsafeAddr data[0]) else: nil
  var rp = if result.len > 0: cast[BytePtr](unsafeAddr result[0]) else: nil
  discard chacha20X(rp, dp, data.len, key, nonce, counter)

proc chacha20H*(key: array[32, byte], input: array[16, byte]): array[32, byte] =
  ## HChaCha20: a specialized hash used to derive a subkey from a key
  ## and a 128-bit input.
  chacha20H(cast[BytePtr](unsafeAddr result[0]), key, input)

proc chacha20HScalar*(key: array[32, byte], input: array[16, byte]): array[32, byte] =
  ## Scalar reference HChaCha20 (never SIMD-accelerated).
  chacha20HScalar(cast[BytePtr](unsafeAddr result[0]), key, input)

# Streaming interface (NimCypher extension: Monocypher 4.0.3 only provides
# the one-shot functions above)
type
  Chacha20Mode* = enum
    chacha20DjbMode, chacha20IetfMode, chacha20XMode

  Chacha20Context* = object
    ## A streaming ChaCha20 state. All three variants collapse to the DJB
    ## form once initialized, so the state always holds an 8-byte nonce.
    mode*: Chacha20Mode
    key*: array[32, byte]
    nonce*: array[8, byte]
    counter*: uint64
    pending: array[64, byte] # tail of an incomplete 64-byte block
    pendingLen: int

proc initChacha20Djb*(ctx: var Chacha20Context, key: array[32, byte],
                      nonce: array[8, byte], counter: uint64 = 0) =
  ## Initialize a ChaCha20 streaming context (DJB variant).
  ctx.mode = chacha20DjbMode
  ctx.key = key
  ctx.nonce = nonce
  ctx.counter = counter
  ctx.pendingLen = 0

proc initChacha20Ietf*(ctx: var Chacha20Context, key: array[32, byte],
                       nonce: array[12, byte], counter: uint32 = 0) =
  ## Initialize a ChaCha20 streaming context (IETF variant). The first four
  ## nonce bytes become the upper 32 bits of the 64-bit stream counter.
  ctx.mode = chacha20IetfMode
  ctx.key = key
  for i in 0 ..< 8:
    ctx.nonce[i] = nonce[i + 4]
  ctx.counter = uint64(counter) +
                 (uint64(load32Le(cast[BytePtr](unsafeAddr nonce[0]))) shl 32)
  ctx.pendingLen = 0

proc initChacha20X*(ctx: var Chacha20Context, key: array[32, byte],
                    nonce: array[24, byte], counter: uint64 = 0) =
  ## Initialize a ChaCha20 streaming context (XChaCha20 variant). The
  ## subkey is derived once from the first 16 nonce bytes.
  ctx.mode = chacha20XMode
  var nonce16: array[16, byte]
  for i in 0 ..< 16:
    nonce16[i] = nonce[i]
  ctx.key = chacha20H(key, nonce16)
  for i in 0 ..< 8:
    ctx.nonce[i] = nonce[16 + i]
  ctx.counter = counter
  ctx.pendingLen = 0

proc chacha20Encrypt*(ctx: var Chacha20Context, dst, src: BytePtr, size: int): int =
  ## Encrypt (or decrypt) `size` bytes of the stream, returning the number
  ## of bytes written to `dst`. The tail of an incomplete 64-byte block is
  ## buffered and written by the next call or by `chacha20Final`, so the
  ## concatenated output always equals the one-shot over the concatenated
  ## input, regardless of chunk boundaries.
  var srcPtr = src
  var srcSize = size
  var outCnt = 0

  # complete a previously buffered partial block
  if ctx.pendingLen > 0:
    let need = 64 - ctx.pendingLen
    let take = min(need, srcSize)
    for i in 0 ..< take:
      ctx.pending[ctx.pendingLen + i] = srcPtr[i]
    srcPtr = srcPtr + take
    srcSize -= take
    ctx.pendingLen += take
    if ctx.pendingLen == 64:
      var tmp: array[64, byte]
      discard chacha20Djb(cast[BytePtr](unsafeAddr tmp[0]),
                          cast[BytePtr](unsafeAddr ctx.pending[0]), 64,
                          ctx.key, ctx.nonce, ctx.counter)
      ctx.counter += 1
      ctx.pendingLen = 0
      for i in 0 ..< 64:
        dst[outCnt + i] = tmp[i]
      outCnt += 64
    else:
      return outCnt

  # full blocks
  let nbBlocks = srcSize shr 6
  if nbBlocks > 0:
    discard chacha20Djb(dst + outCnt, srcPtr, nbBlocks shl 6,
                        ctx.key, ctx.nonce, ctx.counter)
    ctx.counter += uint64(nbBlocks)
    outCnt += nbBlocks shl 6
    srcPtr = srcPtr + (nbBlocks shl 6)
    srcSize -= nbBlocks shl 6

  # buffer the tail
  if srcSize > 0:
    for i in 0 ..< srcSize:
      ctx.pending[i] = srcPtr[i]
    ctx.pendingLen = srcSize

  result = outCnt

proc chacha20Encrypt*(ctx: var Chacha20Context, data: openArray[byte]): seq[byte] =
  ## Encrypt (or decrypt) `data`, returning the emitted ciphertext (or
  ## plaintext). Completing a buffered partial block can emit up to 64 bytes
  ## more than the input. A trailing partial block is buffered; flush it
  ## with `chacha20Final` after the last chunk.
  result = newSeqUninit[byte](data.len + 64)
  var dp = if data.len > 0: cast[BytePtr](unsafeAddr data[0]) else: nil
  var rp = if result.len > 0: cast[BytePtr](unsafeAddr result[0]) else: nil
  result.setLen(chacha20Encrypt(ctx, rp, dp, data.len))

proc chacha20Final*(ctx: var Chacha20Context, dst: BytePtr): int =
  ## Flush the buffered tail of the stream, returning the number of bytes
  ## written to `dst` (0 if no tail was pending).
  let n = ctx.pendingLen
  if n == 0:
    return 0
  var tmp: array[64, byte]
  discard chacha20Djb(cast[BytePtr](unsafeAddr tmp[0]),
                      cast[BytePtr](unsafeAddr ctx.pending[0]), 64,
                      ctx.key, ctx.nonce, ctx.counter)
  ctx.counter += 1
  ctx.pendingLen = 0
  for i in 0 ..< n:
    dst[i] = tmp[i]
  result = n

proc chacha20Final*(ctx: var Chacha20Context): seq[byte] =
  ## Flush the buffered tail of the stream and return it.
  result = newSeqUninit[byte](64)
  result.setLen(chacha20Final(ctx, cast[BytePtr](unsafeAddr result[0])))

{.pop.}
