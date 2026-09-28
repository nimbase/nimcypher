# HKDF key derivation (SHA-512, SHA-256, SHA-384).
#
# Ported from `monocypher-ed25519.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512
import ./sha256
import ./sha384

{.push checks: off.}

proc checkOkmSize(okmSize, hashLen: int) {.inline.} =
  ## RFC 5869 §2.3: output length is bounded by 255 * HashLen. Larger
  ## requests silently wrap the block counter and yield wrong key
  ## material, so every expand entry point enforces the limit.
  if okmSize < 0 or okmSize > 255 * hashLen:
    raise newException(ValueError,
      "HKDF output size out of range 0.." & $(255 * hashLen) &
      ", got " & $okmSize)

proc sha512HkdfExpand*(prk, info: openArray[byte], okmSize: int): seq[byte] =
  ## Expand a pseudo-random key into output keying material.
  ## `okmSize` is limited to 255 * 64 = 16320 bytes (RFC 5869).
  checkOkmSize(okmSize, 64)
  result = newSeq[byte](okmSize)
  var notFirst = 0
  var ctr: byte = 1
  var blk: array[64, byte]
  var offset = 0
  var remaining = okmSize
  while remaining > 0:
    let outSize = min(remaining, 64)
    var ctx: Sha512HmacContext
    initHmac(ctx, prk)
    if notFirst != 0:
      update(ctx, blk)
    update(ctx, info)
    update(ctx, [ctr])
    blk = final(ctx)
    for i in 0 ..< outSize:
      result[offset + i] = blk[i]
    notFirst = 1
    offset += outSize
    remaining -= outSize
    ctr += 1
  wipe(blk)

proc sha512Hkdf*(ikm, salt, info: openArray[byte], okmSize: int): seq[byte] =
  ## HKDF-SHA-512: derive output keying material from an input key
  ## material, a salt and optional info.
  # extract
  var prk = sha512Hmac(salt, ikm)
  # expand
  result = sha512HkdfExpand(prk, info, okmSize)
  wipe(prk)

proc sha256HkdfExpand*(prk, info: openArray[byte], okmSize: int): seq[byte] =
  ## Expand a pseudo-random key with HKDF-SHA-256 (RFC 5869, 32-byte blocks).
  ## `okmSize` is limited to 255 * 32 = 8160 bytes.
  checkOkmSize(okmSize, 32)
  result = newSeq[byte](okmSize)
  var notFirst = 0
  var ctr: byte = 1
  var blk: array[32, byte]
  var offset = 0
  var remaining = okmSize
  while remaining > 0:
    let outSize = min(remaining, 32)
    var ctx: Sha256HmacContext
    initHmac(ctx, prk)
    if notFirst != 0:
      update(ctx, blk)
    update(ctx, info)
    update(ctx, [ctr])
    blk = final(ctx)
    for i in 0 ..< outSize:
      result[offset + i] = blk[i]
    notFirst = 1
    offset += outSize
    remaining -= outSize
    ctr += 1
  wipe(blk)

proc sha256Hkdf*(ikm, salt, info: openArray[byte], okmSize: int): seq[byte] =
  ## HKDF-SHA-256: extract with salt then expand.
  var prk = sha256Hmac(salt, ikm)
  result = sha256HkdfExpand(prk, info, okmSize)
  wipe(prk)

proc sha384HkdfExpand*(prk, info: openArray[byte], okmSize: int): seq[byte] =
  ## Expand a pseudo-random key with HKDF-SHA-384 (RFC 5869, 48-byte blocks).
  ## `okmSize` is limited to 255 * 48 = 12240 bytes.
  checkOkmSize(okmSize, 48)
  result = newSeq[byte](okmSize)
  var notFirst = 0
  var ctr: byte = 1
  var blk: array[48, byte]
  var offset = 0
  var remaining = okmSize
  while remaining > 0:
    let outSize = min(remaining, 48)
    var ctx: Sha384HmacContext
    initHmac384(ctx, prk)
    if notFirst != 0:
      update(ctx, blk)
    update(ctx, info)
    update(ctx, [ctr])
    blk = final(ctx)
    for i in 0 ..< outSize:
      result[offset + i] = blk[i]
    notFirst = 1
    offset += outSize
    remaining -= outSize
    ctr += 1
  wipe(blk)

proc sha384Hkdf*(ikm, salt, info: openArray[byte], okmSize: int): seq[byte] =
  ## HKDF-SHA-384: extract with salt then expand.
  var prk = sha384Hmac(salt, ikm)
  result = sha384HkdfExpand(prk, info, okmSize)
  wipe(prk)

{.pop.}
