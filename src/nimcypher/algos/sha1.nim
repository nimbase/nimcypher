# HMAC-SHA-1 (and internal SHA-1) — pure Nim, no C dependency.
#
# SHA-1 per FIPS 180-4 §6.1, HMAC per RFC 2104. Reference: RFC 3174.
# This file exposes HMAC-SHA-1 as the public primitive; SHA-1 itself is
# internal (used to compress long HMAC keys and as the HMAC hash). No
# streaming API — one-shot only.
#
# Dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common

{.push checks: off.}

const
  Sha1BlockSize* = 64
  Sha1DigestSize* = 20

type
  Sha1Digest* = array[Sha1DigestSize, byte]

proc rotl32(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

proc load32Be(s: BytePtr): uint32 {.inline.} =
  (uint32(s[0]) shl 24) or (uint32(s[1]) shl 16) or
    (uint32(s[2]) shl 8) or uint32(s[3])

proc store32Be(outp: BytePtr, v: uint32) {.inline.} =
  outp[0] = byte(v shr 24)
  outp[1] = byte(v shr 16)
  outp[2] = byte(v shr 8)
  outp[3] = byte(v)

# SHA-1 compression: 80 rounds, 512-bit block in W[0..15] BE.
proc sha1Compress(h: var array[5, uint32], blk: BytePtr) {.inline.} =
  var w: array[80, uint32]
  for i in 0 ..< 16:
    w[i] = load32Be(blk + i * 4)
  for i in 16 ..< 80:
    w[i] = rotl32(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

  var a = h[0]
  var b = h[1]
  var c = h[2]
  var d = h[3]
  var e = h[4]

  for i in 0 ..< 80:
    var f, k: uint32
    if i < 20:
      f = (b and c) or ((not b) and d)
      k = 0x5A827999'u32
    elif i < 40:
      f = b xor c xor d
      k = 0x6ED9EBA1'u32
    elif i < 60:
      f = (b and c) or (b and d) or (c and d)
      k = 0x8F1BBCDC'u32
    else:
      f = b xor c xor d
      k = 0xCA62C1D6'u32
    let temp = rotl32(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = temp

  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
  h[4] += e

proc sha1*(message: openArray[byte]): Sha1Digest =
  ## Internal SHA-1 (FIPS 180-4). Not exported at high level; used by HMAC.
  var h: array[5, uint32] = [
    0x67452301'u32, 0xEFCDAB89'u32, 0x98BADCFE'u32, 0x10325476'u32, 0xC3D2E1F0'u32
  ]
  let ml = message.len
  let bitLen = uint64(ml) * 8
  # padded length = smallest multiple of 64 >= ml+1+8
  let paddedLen = ((ml + 1 + 8 + 63) div 64) * 64
  var padded = newSeq[byte](paddedLen)
  if ml > 0:
    # copyMem with nil guard
    copyMem(addr padded[0], unsafeAddr message[0], ml)
  padded[ml] = 0x80
  # last 8 bytes = bitLen BE (zero-filled gap already)
  let off = paddedLen - 8
  padded[off+0] = byte(bitLen shr 56)
  padded[off+1] = byte(bitLen shr 48)
  padded[off+2] = byte(bitLen shr 40)
  padded[off+3] = byte(bitLen shr 32)
  padded[off+4] = byte(bitLen shr 24)
  padded[off+5] = byte(bitLen shr 16)
  padded[off+6] = byte(bitLen shr 8)
  padded[off+7] = byte(bitLen)

  var blkPtr = cast[BytePtr](addr padded[0])
  var offset = 0
  while offset < paddedLen:
    sha1Compress(h, blkPtr + offset)
    offset += 64

  # wipe padded material
  wipe(padded)
  for i in 0 ..< 5:
    store32Be(cast[BytePtr](addr result[i*4]), h[i])
  wipe(h)

proc sha1Hmac*(key, message: openArray[byte]): Sha1Digest =
  ## Compute HMAC-SHA-1 of `message` under `key` (RFC 2104).
  ## One-shot only; no streaming context.
  var blockKey: array[Sha1BlockSize, byte]
  var keyLen = key.len
  if keyLen > Sha1BlockSize:
    let hashed = sha1(key)
    for i in 0 ..< Sha1DigestSize:
      blockKey[i] = hashed[i]
    keyLen = Sha1DigestSize
  elif keyLen > 0:
    copyMem(addr blockKey[0], unsafeAddr key[0], keyLen)
  elif keyLen == 0:
    discard

  var ipad: array[Sha1BlockSize, byte]
  var opad: array[Sha1BlockSize, byte]
  for i in 0 ..< Sha1BlockSize:
    ipad[i] = blockKey[i] xor 0x36
    opad[i] = blockKey[i] xor 0x5c

  # inner = SHA1(ipad || message)
  let innerLen = Sha1BlockSize + message.len
  var innerInput = newSeq[byte](innerLen)
  copyMem(addr innerInput[0], addr ipad[0], Sha1BlockSize)
  if message.len > 0:
    copyMem(addr innerInput[Sha1BlockSize], unsafeAddr message[0], message.len)
  let inner = sha1(innerInput)
  wipe(innerInput)
  wipe(ipad)

  # outer = SHA1(opad || inner)
  var outerInput = newSeq[byte](Sha1BlockSize + Sha1DigestSize)
  copyMem(addr outerInput[0], addr opad[0], Sha1BlockSize)
  copyMem(addr outerInput[Sha1BlockSize], unsafeAddr inner[0], Sha1DigestSize)
  result = sha1(outerInput)
  wipe(outerInput)
  wipe(opad)
  var innerMut = inner
  wipe(innerMut)
  wipe(blockKey)

{.pop.}
