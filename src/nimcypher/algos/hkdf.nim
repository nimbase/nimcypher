# HKDF-SHA-512 key derivation.
#
# Ported from `monocypher-ed25519.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512

{.push checks: off.}

proc sha512HkdfExpand*(prk, info: openArray[byte], okmSize: int): seq[byte] =
  ## Expand a pseudo-random key into output keying material.
  ## `okmSize` is limited to 255 * 64 = 16320 bytes (RFC 5869); larger
  ## requests silently wrap the block counter and yield wrong key material.
  ## Callers must enforce the limit (see `nimcypher/hash`).
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

{.pop.}
