# Hardware AES kernels: AES-NI on amd64, ARMv8 Crypto Extensions on arm64.
#
# Compiled only when `features.nimcypher.nimsimd` is defined (see
# nimcypher.nimble and src/nimcypher/algos/aes.nim). The scalar constant-time
# bitsliced kernel in `aes.nim` always stays available as the reference; the
# hardware path is cross-checked against it (and the NIST vectors) by the
# test suite.
#
# The kernels consume a conventional byte-image round-key schedule
# (`AesContext.nrk`, plus its InvMixColumns form `nrkInv` for decryption),
# which `initAes` fills alongside the bitsliced schedule. Blocks are
# processed in independent-register batches so the out-of-order engine can
# overlap the round chains.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../common

when defined(amd64):
  {.passC: "-maes".}
  import nimsimd/sse2

  {.push header: "wmmintrin.h".}
  func mm_aesenc_si128(a, k: M128i): M128i {.importc: "_mm_aesenc_si128".}
  func mm_aesenclast_si128(a, k: M128i): M128i {.importc: "_mm_aesenclast_si128".}
  func mm_aesdec_si128(a, k: M128i): M128i {.importc: "_mm_aesdec_si128".}
  func mm_aesdeclast_si128(a, k: M128i): M128i {.importc: "_mm_aesdeclast_si128".}
  {.pop.}

  template loadRk(nrk: pointer, r: int): M128i =
    mm_loadu_si128(cast[ptr M128i](cast[uint](nrk) + uint(r * 16)))

  proc encBatch8(rounds: int, nrk: pointer, dst, src: BytePtr) {.inline.} =
    ## Encrypt exactly 8 blocks (independent states share the round chain).
    var s: array[8, M128i]
    for i in 0 ..< 8:
      s[i] = mm_loadu_si128(cast[ptr M128i](src + i * 16))
      s[i] = mm_xor_si128(s[i], loadRk(nrk, 0))
    for r in 1 ..< rounds:
      let k = loadRk(nrk, r)
      for i in 0 ..< 8:
        s[i] = mm_aesenc_si128(s[i], k)
    let k = loadRk(nrk, rounds)
    for i in 0 ..< 8:
      s[i] = mm_aesenclast_si128(s[i], k)
      mm_storeu_si128(cast[ptr M128i](dst + i * 16), s[i])

  proc decBatch8(rounds: int, nrk: pointer, nrkInv: pointer,
                 dst, src: BytePtr) {.inline.} =
    ## Decrypt exactly 8 blocks using the equivalent inverse cipher
    ## (`nrkInv` holds the InvMixColumns-transformed middle keys).
    var s: array[8, M128i]
    for i in 0 ..< 8:
      s[i] = mm_loadu_si128(cast[ptr M128i](src + i * 16))
      s[i] = mm_xor_si128(s[i], loadRk(nrk, rounds))
    for r in countdown(rounds - 1, 1):
      let k = loadRk(nrkInv, r)
      for i in 0 ..< 8:
        s[i] = mm_aesdec_si128(s[i], k)
    let k = loadRk(nrk, 0)
    for i in 0 ..< 8:
      s[i] = mm_aesdeclast_si128(s[i], k)
      mm_storeu_si128(cast[ptr M128i](dst + i * 16), s[i])

elif defined(arm64):
  import nimsimd/neon

  # nimsimd/neon does not vendor the cryptographic extensions.
  {.push header: "arm_neon.h".}
  func vaeseq_u32(a, k: uint8x16): uint8x16 {.importc: "vaeseq_u32".}
  func vaesmcq_u32(a: uint8x16): uint8x16 {.importc: "vaesmcq_u32".}
  func vaesdq_u32(a, k: uint8x16): uint8x16 {.importc: "vaesdq_u32".}
  func vaesimcq_u32(a: uint8x16): uint8x16 {.importc: "vaesimcq_u32".}
  {.pop.}

  proc encBatch4(rounds: int, nrk: pointer, dst, src: BytePtr) {.inline.} =
    ## Encrypt exactly 4 blocks. AESE covers SubBytes + ShiftRows +
    ## AddRoundKey(key argument); AESMC applies MixColumns.
    var s: array[4, uint8x16]
    for i in 0 ..< 4:
      s[i] = vld1q_u8(src + i * 16)
    for r in 0 ..< rounds - 1:
      let k = vld1q_u8(cast[pointer](cast[uint](nrk) + uint(r * 16)))
      for i in 0 ..< 4:
        s[i] = vaesmcq_u32(vaeseq_u32(s[i], k))
    let k1 = vld1q_u8(cast[pointer](cast[uint](nrk) +
                                      uint((rounds - 1) * 16)))
    let k2 = vld1q_u8(cast[pointer](cast[uint](nrk) + uint(rounds * 16)))
    for i in 0 ..< 4:
      s[i] = veorq_u8(vaeseq_u32(s[i], k1), k2)
      vst1q_u8(dst + i * 16, s[i])

  proc decBatch4(rounds: int, nrk: pointer, nrkInv: pointer,
                 dst, src: BytePtr) {.inline.} =
    ## Decrypt exactly 4 blocks via the equivalent inverse cipher.
    var s: array[4, uint8x16]
    for i in 0 ..< 4:
      s[i] = vld1q_u8(src + i * 16)
    for r in countdown(rounds - 1, 1):
      let k = vld1q_u8(cast[pointer](cast[uint](nrkInv) + uint(r * 16)))
      for i in 0 ..< 4:
        s[i] = vaesimcq_u32(vaesdq_u32(s[i], k))
    let k1 = vld1q_u8(nrkInv)
    let k2 = vld1q_u8(nrk)
    for i in 0 ..< 4:
      s[i] = veorq_u8(vaesdq_u32(s[i], k1), k2)
      vst1q_u8(dst + i * 16, s[i])

else:
  {.error: "aes_simd requires amd64 or arm64.".}

const hwBatchBlocks* = when defined(amd64): 8 else: 4

template batchTail(encrypting: static bool) {.dirty.} =
  var inp, outp: array[hwBatchBlocks * 16, byte]
  copyMem(addr inp[0], src + off, left * 16)
  var p = left * 16
  while p < inp.len:
    let take = min(left * 16, inp.len - p)
    copyMem(addr inp[p], addr inp[0], take)
    p += take
  when encrypting:
    when defined(amd64):
      encBatch8(rounds, nrk, cast[BytePtr](addr outp[0]),
                cast[BytePtr](addr inp[0]))
    else:
      encBatch4(rounds, nrk, cast[BytePtr](addr outp[0]),
                cast[BytePtr](addr inp[0]))
  else:
    when defined(amd64):
      decBatch8(rounds, nrk, nrkInv, cast[BytePtr](addr outp[0]),
                cast[BytePtr](addr inp[0]))
    else:
      decBatch4(rounds, nrk, nrkInv, cast[BytePtr](addr outp[0]),
                cast[BytePtr](addr inp[0]))
  copyMem(dst + off, addr outp[0], left * 16)
  wipe(inp)
  wipe(outp)

proc encryptBlocksSimd*(rounds: int, nrk: pointer, dst, src: BytePtr,
                        nb: int) =
  ## Encrypt `nb` blocks from `src` into `dst` (`nb >= 1`). Full batches run
  ## in place; the tail batch is padded by replicating its blocks inside
  ## scratch memory (extra outputs are discarded).
  var off = 0
  var left = nb
  while left >= hwBatchBlocks:
    when defined(amd64):
      encBatch8(rounds, nrk, dst + off, src + off)
    else:
      encBatch4(rounds, nrk, dst + off, src + off)
    off += hwBatchBlocks * 16
    left -= hwBatchBlocks
  if left > 0:
    batchTail(true)

proc decryptBlocksSimd*(rounds: int, nrk: pointer, nrkInv: pointer,
                        dst, src: BytePtr, nb: int) =
  ## Decrypt `nb` blocks from `src` into `dst` (`nb >= 1`).
  var off = 0
  var left = nb
  while left >= hwBatchBlocks:
    when defined(amd64):
      decBatch8(rounds, nrk, nrkInv, dst + off, src + off)
    else:
      decBatch4(rounds, nrk, nrkInv, dst + off, src + off)
    off += hwBatchBlocks * 16
    left -= hwBatchBlocks
  if left > 0:
    batchTail(false)
