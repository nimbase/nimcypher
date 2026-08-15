# ChaCha20 stream cipher.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

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

proc chacha20Rounds(outp: var array[16, uint32], inp: array[16, uint32]) {.inline.} =
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

proc chacha20Djb*(cipherText: BytePtr, plainText: BytePtr, textSize: int,
                  key: array[32, byte], nonce: array[8, byte],
                  ctr: uint64): uint64 =
  var inputBuf: array[16, uint32]
  load32LeBuf(inputBuf, cast[BytePtr](unsafeAddr chacha20Constant[0]), 4)
  load32LeBuf(inputBuf.toOpenArray(4, 11),
              cast[BytePtr](unsafeAddr key[0]), 8)
  load32LeBuf(inputBuf.toOpenArray(14, 15),
              cast[BytePtr](unsafeAddr nonce[0]), 2)
  inputBuf[12] = uint32(ctr)
  inputBuf[13] = uint32(ctr shr 32)

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

{.pop.}
