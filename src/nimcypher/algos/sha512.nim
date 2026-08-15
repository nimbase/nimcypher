# SHA-512 hash and HMAC.
#
# Ported from `monocypher-ed25519.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

type
  Sha512Context* = object
    hash*: array[8, uint64]
    input*: array[16, uint64]
    inputSize*: array[2, uint64]
    inputIdx*: int

  Sha512HmacContext* = object
    key: array[128, byte]
    ctx: Sha512Context

proc rot(x: uint64, c: int): uint64 {.inline.} =
  result = (x shr c) or (x shl (64 - c))

proc ch(x, y, z: uint64): uint64 {.inline.} = (x and y) xor (not x and z)
proc maj(x, y, z: uint64): uint64 {.inline.} = (x and y) xor (x and z) xor (y and z)
proc bigSigma0(x: uint64): uint64 {.inline.} = rot(x, 28) xor rot(x, 34) xor rot(x, 39)
proc bigSigma1(x: uint64): uint64 {.inline.} = rot(x, 14) xor rot(x, 18) xor rot(x, 41)
proc litSigma0(x: uint64): uint64 {.inline.} = rot(x, 1) xor rot(x, 8) xor (x shr 7)
proc litSigma1(x: uint64): uint64 {.inline.} = rot(x, 19) xor rot(x, 61) xor (x shr 6)

const
  K: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64,
    0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64, 0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64,
    0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64, 0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64, 0xc19bf174cf692694'u64,
    0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64, 0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
    0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64,
    0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64, 0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64,
    0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
    0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64, 0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64,
    0xd192e819d6ef5218'u64, 0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64, 0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64,
    0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64, 0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64,
    0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64,
    0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64, 0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64,
    0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64, 0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64, 0x431d67c49c100d4c'u64,
    0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64, 0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64,
  ]

proc sha512Compress(ctx: var Sha512Context) {.inline.} =
  var a = ctx.hash[0]; var b = ctx.hash[1]
  var c = ctx.hash[2]; var d = ctx.hash[3]
  var e = ctx.hash[4]; var f = ctx.hash[5]
  var g = ctx.hash[6]; var h = ctx.hash[7]
  for j in 0 ..< 16:
    let input = K[j] + ctx.input[j]
    let t1 = bigSigma1(e) + ch(e, f, g) + h + input
    let t2 = bigSigma0(a) + maj(a, b, c)
    h = g; g = f; f = e; e = d + t1
    d = c; c = b; b = a; a = t1 + t2
  var i16 = 0
  for i in 1 ..< 5:
    i16 += 16
    for j in 0 ..< 16:
      ctx.input[j] += litSigma1(ctx.input[(j - 2) and 15])
      ctx.input[j] += litSigma0(ctx.input[(j - 15) and 15])
      ctx.input[j] += ctx.input[(j - 7) and 15]
      let input = K[i16 + j] + ctx.input[j]
      let t1 = bigSigma1(e) + ch(e, f, g) + h + input
      let t2 = bigSigma0(a) + maj(a, b, c)
      h = g; g = f; f = e; e = d + t1
      d = c; c = b; b = a; a = t1 + t2
  ctx.hash[0] += a; ctx.hash[1] += b
  ctx.hash[2] += c; ctx.hash[3] += d
  ctx.hash[4] += e; ctx.hash[5] += f
  ctx.hash[6] += g; ctx.hash[7] += h

proc load64Be(s: BytePtr): uint64 =
  result = (uint64(s[0]) shl 56) or (uint64(s[1]) shl 48) or
           (uint64(s[2]) shl 40) or (uint64(s[3]) shl 32) or
           (uint64(s[4]) shl 24) or (uint64(s[5]) shl 16) or
           (uint64(s[6]) shl 8) or uint64(s[7])

proc store64Be(outp: BytePtr, input: uint64) =
  outp[0] = byte(input shr 56)
  outp[1] = byte(input shr 48)
  outp[2] = byte(input shr 40)
  outp[3] = byte(input shr 32)
  outp[4] = byte(input shr 24)
  outp[5] = byte(input shr 16)
  outp[6] = byte(input shr 8)
  outp[7] = byte(input)

proc load64BeBuf(dst: var openArray[uint64], src: BytePtr, size: int) =
  for i in 0 ..< size:
    dst[i] = load64Be(src + i * 8)

# write 1 input byte
proc setInput(ctx: var Sha512Context, input: byte) =
  let word = ctx.inputIdx shr 3
  let byte = ctx.inputIdx and 7
  ctx.input[word] = ctx.input[word] or
                    (uint64(input) shl (8 * (7 - byte)))

# increment a 128-bit "word"
proc incr(x: var array[2, uint64], y: uint64) =
  x[1] += y
  if x[1] < y:
    x[0] += 1

proc init*(ctx: var Sha512Context) =
  ctx.hash[0] = 0x6a09e667f3bcc908'u64
  ctx.hash[1] = 0xbb67ae8584caa73b'u64
  ctx.hash[2] = 0x3c6ef372fe94f82b'u64
  ctx.hash[3] = 0xa54ff53a5f1d36f1'u64
  ctx.hash[4] = 0x510e527fade682d1'u64
  ctx.hash[5] = 0x9b05688c2b3e6c1f'u64
  ctx.hash[6] = 0x1f83d9abfb41bd6b'u64
  ctx.hash[7] = 0x5be0cd19137e2179'u64
  ctx.inputSize[0] = 0
  ctx.inputSize[1] = 0
  ctx.inputIdx = 0
  ctx.input = default(array[16, uint64])

proc update*(ctx: var Sha512Context, message: openArray[byte]) =
  if message.len == 0:
    return
  var msg = cast[BytePtr](unsafeAddr message[0])
  var msgSize = message.len

  # align ourselves with word boundaries
  if (ctx.inputIdx and 7) != 0:
    let nbBytes = min(gap(ctx.inputIdx, 8), msgSize)
    for i in 0 ..< nbBytes:
      setInput(ctx, msg[i])
      ctx.inputIdx += 1
    msg = msg + nbBytes
    msgSize -= nbBytes

  # align ourselves with block boundaries
  if (ctx.inputIdx and 127) != 0:
    let nbWords = min(gap(ctx.inputIdx, 128), msgSize) shr 3
    load64BeBuf(ctx.input.toOpenArray(ctx.inputIdx shr 3,
                                      ctx.inputIdx shr 3 + nbWords - 1),
                msg, nbWords)
    ctx.inputIdx += nbWords shl 3
    msg = msg + (nbWords shl 3)
    msgSize -= nbWords shl 3

  # compress block if needed
  if ctx.inputIdx == 128:
    incr(ctx.inputSize, 1024) # size is in bits
    sha512Compress(ctx)
    ctx.inputIdx = 0
    ctx.input = default(array[16, uint64])

  # process the message block by block
  let nbBlocks = msgSize shr 7
  for i in 0 ..< nbBlocks:
    load64BeBuf(ctx.input.toOpenArray(0, 15), msg, 16)
    incr(ctx.inputSize, 1024) # size is in bits
    sha512Compress(ctx)
    ctx.inputIdx = 0
    ctx.input = default(array[16, uint64])
    msg = msg + 128
  msgSize = msgSize and 127

  if msgSize != 0:
    # remaining words
    let nbWords = msgSize shr 3
    load64BeBuf(ctx.input.toOpenArray(0, nbWords - 1), msg, nbWords)
    ctx.inputIdx += nbWords shl 3
    msg = msg + (nbWords shl 3)
    msgSize -= nbWords shl 3
    # remaining bytes
    for i in 0 ..< msgSize:
      setInput(ctx, msg[i])
      ctx.inputIdx += 1

proc final*(ctx: var Sha512Context): array[64, byte] =
  # add padding bit
  if ctx.inputIdx == 0:
    ctx.input = default(array[16, uint64])
  setInput(ctx, 128)

  # update size
  incr(ctx.inputSize, uint64(ctx.inputIdx) * 8)

  # compress penultimate block (if any)
  if ctx.inputIdx > 111:
    sha512Compress(ctx)
    ctx.input[0] = 0
    ctx.input[1] = 0
    ctx.input[2] = 0
    ctx.input[3] = 0
    ctx.input[4] = 0
    ctx.input[5] = 0
    ctx.input[6] = 0
    ctx.input[7] = 0
    ctx.input[8] = 0
    ctx.input[9] = 0
    ctx.input[10] = 0
    ctx.input[11] = 0
    ctx.input[12] = 0
    ctx.input[13] = 0
  # compress last block
  ctx.input[14] = ctx.inputSize[0]
  ctx.input[15] = ctx.inputSize[1]
  sha512Compress(ctx)

  # copy hash to output (big endian)
  for i in 0 ..< 8:
    store64Be(cast[BytePtr](unsafeAddr result[i * 8]), ctx.hash[i])
  wipe(ctx)

proc sha512*(message: openArray[byte]): array[64, byte] =
  ## Compute the SHA-512 hash of `message`.
  var ctx: Sha512Context
  init(ctx)
  update(ctx, message)
  result = final(ctx)

# HMAC SHA-512

proc initHmac*(ctx: var Sha512HmacContext, key: openArray[byte]) =
  ## Initialize an HMAC-SHA-512 context with the given key.
  var keyPtr: BytePtr = nil
  var keySize = key.len
  # hash the key if it is too long
  if keySize > 128:
    let hashed = sha512(key)
    for i in 0 ..< 64:
      ctx.key[i] = hashed[i]
    keyPtr = cast[BytePtr](unsafeAddr ctx.key[0])
    keySize = 64
  elif keySize > 0:
    keyPtr = cast[BytePtr](unsafeAddr key[0])
  # keySize == 0 keeps keyPtr nil: an empty key is the 128 zero bytes
  # padded with 0x36, and the loop below copies nothing.
  # compute inner key: padded key XOR 0x36
  for i in 0 ..< keySize:
    ctx.key[i] = keyPtr[i] xor 0x36
  for i in keySize ..< 128:
    ctx.key[i] = 0x36
  # start computing inner hash
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)

proc update*(ctx: var Sha512HmacContext, message: openArray[byte]) =
  update(ctx.ctx, message)

proc final*(ctx: var Sha512HmacContext): array[64, byte] =
  ## Compute the 64-byte HMAC.
  result = final(ctx.ctx)
  # compute outer key: padded key XOR 0x5c
  for i in 0 ..< 128:
    ctx.key[i] = ctx.key[i] xor (0x36 xor 0x5c)
  # compute outer hash
  init(ctx.ctx)
  update(ctx.ctx, ctx.key)
  update(ctx.ctx, result)
  result = final(ctx.ctx)
  wipe(ctx)

proc sha512Hmac*(key, message: openArray[byte]): array[64, byte] =
  ## Compute an HMAC-SHA-512 of `message`.
  var ctx: Sha512HmacContext
  initHmac(ctx, key)
  update(ctx, message)
  result = final(ctx)

{.pop.}
