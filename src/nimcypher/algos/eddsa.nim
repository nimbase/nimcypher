# EdDSA signatures with Curve25519 and BLAKE2b.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./blake2b
import ./internal/fe
import ./internal/edl
import ./internal/ge

{.push checks: off.}

proc trimScalar*(scalar: array[32, byte]): array[32, byte] =
  ## Trim a scalar for scalar multiplication.
  trimScalar(cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr scalar[0]))

proc trimScalar(a: var array[64, byte]) =
  trimScalar(cast[BytePtr](unsafeAddr a[0]),
             cast[BytePtr](unsafeAddr a[0]))

proc reduce*(expanded: openArray[byte]): array[32, byte] =
  ## Reduce a 64-byte scalar modulo L.
  var x: array[16, uint32]
  load32LeBuf(x.toOpenArray(0, 15), cast[BytePtr](unsafeAddr expanded[0]), 16)
  modL(cast[BytePtr](unsafeAddr result[0]), x)
  wipe(x)

proc mulAdd*(a, b, c: openArray[byte]): array[32, byte] =
  ## Compute (a * b + c) modulo L.
  mulAdd(cast[BytePtr](unsafeAddr result[0]),
         cast[BytePtr](unsafeAddr a[0]),
         cast[BytePtr](unsafeAddr b[0]),
         cast[BytePtr](unsafeAddr c[0]))

proc scalarbase*(scalar: openArray[byte]): array[32, byte] =
  ## Compute [scalar]B, the scalar multiple of the base point.
  var P: Ge
  geScalarmultBase(P, cast[BytePtr](unsafeAddr scalar[0]))
  geTobytes(cast[BytePtr](unsafeAddr result[0]), P)
  wipe(P)

proc hashReduce(h: var array[32, byte], a, b, c: openArray[byte]) =
  var ctx: Blake2bContext
  init(ctx, 64)
  update(ctx, a)
  update(ctx, b)
  update(ctx, c)
  h = reduce(final(ctx))

proc eddsaKeyPair*(seed: array[32, byte]): (array[64, byte], array[32, byte]) =
  ## Generate an EdDSA key pair from a seed.
  ## Returns (secret_key, public_key).
  var a: array[64, byte]
  for i in 0 ..< 32:
    a[i] = seed[i]
    result[0][i] = seed[i]
  # a = blake2b(seed, 64)
  let ah = blake2b(a.toOpenArray(0, 31), 64)
  for i in 0 ..< 64:
    a[i] = ah[i]
  trimScalar(a)
  result[1] = scalarbase(a.toOpenArray(0, 31))
  for i in 0 ..< 32:
    result[0][32 + i] = result[1][i]
  wipe(a)

proc eddsaSign*(message: openArray[byte], secretKey: array[64, byte]):
    array[64, byte] =
  ## Sign a message with a secret key. The secret key bundles the seed
  ## (bytes 0..31) and the public key (bytes 32..63).
  var a: array[64, byte] # secret scalar and prefix
  var r: array[32, byte] # secret deterministic "random" nonce
  var h: array[32, byte]
  var R: array[32, byte]
  let ah = blake2b(secretKey.toOpenArray(0, 31), 64)
  for i in 0 ..< 64:
    a[i] = ah[i]
  trimScalar(a)
  hashReduce(r, a.toOpenArray(32, 63), message, [])
  R = scalarbase(r)
  hashReduce(h, R, secretKey.toOpenArray(32, 63), message)
  for i in 0 ..< 32:
    result[i] = R[i]
  let s = mulAdd(h, a.toOpenArray(0, 31), r)
  for i in 0 ..< 32:
    result[32 + i] = s[i]
  wipe(a)
  wipe(r)

proc checkEquation*(signature: array[64, byte], publicKey: array[32, byte],
                    h: array[32, byte]): bool =
  ## Check the equation [s]B == R + [h]A for the given signature,
  ## public key and challenge.
  var minusA, minusR: Ge
  var s32: array[8, uint32]
  load32LeBuf(s32.toOpenArray(0, 7),
              cast[BytePtr](unsafeAddr signature[32]), 8)
  if geFrombytesNegVartime(minusA, cast[BytePtr](unsafeAddr publicKey[0])) != 0 or
     geFrombytesNegVartime(minusR, cast[BytePtr](unsafeAddr signature[0])) != 0 or
     isAboveL(s32) != 0:
    return false

  # look-up table for minus_A
  var lutA: array[P_W_SIZE, GeCached]
  block:
    var minusA2, tmp: Ge
    geDouble(minusA2, minusA, tmp)
    geCache(lutA[0], minusA)
    for i in 1 ..< P_W_SIZE:
      geAdd(tmp, minusA2, lutA[i - 1])
      geCache(lutA[i], tmp)

  # sum = [s]B - [h]A
  # merged double and add ladder, fused with sliding
  var hSlide: SlideCtx
  slideInit(hSlide, cast[BytePtr](unsafeAddr h[0]))
  var sSlide: SlideCtx
  slideInit(sSlide, cast[BytePtr](unsafeAddr signature[32]))
  var i = max(int(hSlide.nextCheck), int(sSlide.nextCheck))
  var sum = minusA # reuse minus_A for the sum
  geZero(sum)
  while i >= 0:
    var tmp: Ge
    geDouble(sum, sum, tmp)
    let hDigit = slideStep(hSlide, P_W_WIDTH, i,
                           cast[BytePtr](unsafeAddr h[0]))
    let sDigit = slideStep(sSlide, B_W_WIDTH, i,
                           cast[BytePtr](unsafeAddr signature[32]))
    if hDigit > 0:
      geAdd(sum, sum, lutA[hDigit div 2])
    if hDigit < 0:
      geSub(sum, sum, lutA[(-hDigit) div 2])
    var t1, t2: Fe
    if sDigit > 0:
      geMadd(sum, sum, bWindow[sDigit div 2], t1, t2)
    if sDigit < 0:
      geMsub(sum, sum, bWindow[(-sDigit) div 2], t1, t2)
    i -= 1

  # compare [8](sum-R) and the zero point
  var cached: GeCached
  var check: array[32, byte]
  var zeroPoint: array[32, byte]
  zeroPoint[0] = 1 # point of order 1
  geCache(cached, minusR)
  geAdd(sum, sum, cached)
  geDouble(sum, sum, minusR)
  geDouble(sum, sum, minusR)
  geDouble(sum, sum, minusR)
  geTobytes(cast[BytePtr](unsafeAddr check[0]), sum)
  result = constantTimeEqual(check, zeroPoint)

proc eddsaCheck*(signature: array[64, byte], publicKey: array[32, byte],
                 message: openArray[byte]): bool =
  ## Verify an EdDSA signature. Returns true if valid.
  var h: array[32, byte]
  hashReduce(h, signature.toOpenArray(0, 31), publicKey, message)
  result = checkEquation(signature, publicKey, h)

proc eddsaPhSign*(messageHash: array[64, byte], secretKey: array[64, byte]):
    array[64, byte] =
  ## Sign a pre-hashed message (BLAKE2b-based EdDSAph, RFC 8032).
  ## `messageHash` is the 64-byte BLAKE2b hash of the message.
  ## NimCypher extension: Monocypher 4.0.3 only provides the SHA-512
  ## variant (`ed25519PhSign`).
  eddsaSign(messageHash.toOpenArray(0, 63), secretKey)

proc eddsaPhCheck*(signature: array[64, byte], publicKey: array[32, byte],
                   messageHash: array[64, byte]): bool =
  ## Verify a BLAKE2b-based EdDSAph signature of a pre-hashed message.
  eddsaCheck(signature, publicKey, messageHash.toOpenArray(0, 63))

{.pop.}
