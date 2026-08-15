# X25519 key exchange and related conversions.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./internal/fe
import ./internal/edl
import ./internal/ge

{.push checks: off.}

proc x25519*(yourSecretKey, theirPublicKey: array[32, byte]): array[32, byte] =
  ## Compute an X25519 shared secret. Hash the result to derive an
  ## actual shared key.
  var e: array[32, byte]
  trimScalar(cast[BytePtr](unsafeAddr e[0]),
             cast[BytePtr](unsafeAddr yourSecretKey[0]))
  scalarmult(cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr e[0]),
             cast[BytePtr](unsafeAddr theirPublicKey[0]), 255)
  wipe(e)

proc x25519PublicKey*(secretKey: array[32, byte]): array[32, byte] =
  ## Compute the public key corresponding to a secret key.
  var basePoint: array[32, byte]
  basePoint[0] = 9
  result = x25519(secretKey, basePoint)

proc x25519Inverse*(privateKey, curvePoint: array[32, byte]): array[32, byte] =
  ## Compute the scalar inverse of `privateKey` at `curvePoint`
  ## (OPRF support). Be aware that exponential blinding is less secure
  ## than Diffie-Hellman key exchange.
  const
    Lm2: array[32, byte] = [ # L - 2
      byte 0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]
    mInv: array[8, uint32] = [ # 1 in Montgomery form
      0x8d98951d'u32, 0xd6ec3174'u32, 0x737dcf70'u32, 0xc6ef5bf4'u32,
      0xfffffffe'u32, 0xffffffff'u32, 0xffffffff'u32, 0x0fffffff'u32,
    ]
  var scalar: array[32, byte]
  trimScalar(cast[BytePtr](unsafeAddr scalar[0]),
             cast[BytePtr](unsafeAddr privateKey[0]))

  # convert the scalar in Montgomery form: m_scl = scalar * 2^256 mod L
  var mScl: array[8, uint32]
  block:
    var tmp: array[16, uint32]
    for i in 0 ..< 8:
      tmp[i] = 0
    load32LeBuf(tmp.toOpenArray(8, 15),
                cast[BytePtr](unsafeAddr scalar[0]), 8)
    modL(cast[BytePtr](unsafeAddr scalar[0]), tmp)
    load32LeBuf(mScl.toOpenArray(0, 7),
                cast[BytePtr](unsafeAddr scalar[0]), 8)
    wipe(tmp)

  # compute the inverse
  var product: array[16, uint32]
  var mInvLocal = mInv
  for i in countdown(252, 0):
    product = default(array[16, uint32])
    multiply(product, mInvLocal, mInvLocal)
    redc(mInvLocal, product)
    if scalarBit(cast[BytePtr](unsafeAddr Lm2[0]), i) != 0:
      product = default(array[16, uint32])
      multiply(product, mInvLocal, mScl)
      redc(mInvLocal, product)

  # convert the inverse *out* of Montgomery form
  for i in 0 ..< 8:
    product[i] = mInvLocal[i]
  for i in 8 ..< 16:
    product[i] = 0
  redc(mInvLocal, product)
  store32LeBuf(cast[BytePtr](unsafeAddr scalar[0]),
               mInvLocal.toOpenArray(0, 7), 8) # the inverse of the scalar

  # clear the cofactor of scalar
  addXL(cast[BytePtr](unsafeAddr scalar[0]),
        byte(scalar[0] * 3))

  # 8*L < 2^256, so span the ladder over 256 bits
  scalarmult(cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr scalar[0]),
             cast[BytePtr](unsafeAddr curvePoint[0]), 256)

  wipe(scalar)
  wipe(mScl)
  wipe(product)
  wipe(mInvLocal)

proc x25519DirtySmall*(secretKey: array[32, byte]): array[32, byte] =
  ## "Dirty" ephemeral public key (small version). Leaks 3 bits of the
  ## private key. Use only with `elligatorRev`.
  const
    dirtyBasePoint: array[32, byte] = [
      byte 0xd8, 0x86, 0x1a, 0xa2, 0x78, 0x7a, 0xd9, 0x26,
      0x8b, 0x74, 0x74, 0xb6, 0x82, 0xe3, 0xbe, 0xc3,
      0xce, 0x36, 0x9a, 0x1e, 0x5e, 0x31, 0x47, 0xa2,
      0x6d, 0x37, 0x7c, 0xfd, 0x20, 0xb5, 0xdf, 0x75,
    ]
  var scalar: array[32, byte]
  trimScalar(cast[BytePtr](unsafeAddr scalar[0]),
             cast[BytePtr](unsafeAddr secretKey[0]))
  # separate the main factor and the cofactor
  addXL(cast[BytePtr](unsafeAddr scalar[0]), secretKey[0])
  scalarmult(cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr scalar[0]),
             cast[BytePtr](unsafeAddr dirtyBasePoint[0]), 256)
  wipe(scalar)

proc x25519DirtyFast*(secretKey: array[32, byte]): array[32, byte] =
  ## "Dirty" ephemeral public key (fast version). Leaks 3 bits of the
  ## private key. Use only with `elligatorRev`.
  # compute clean scalar multiplication
  var scalar: array[32, byte]
  var pk: Ge
  trimScalar(cast[BytePtr](unsafeAddr scalar[0]),
             cast[BytePtr](unsafeAddr secretKey[0]))
  geScalarmultBase(pk, cast[BytePtr](unsafeAddr scalar[0]))

  # compute low order point
  var t1, t2: Fe
  selectLop(t1, lopX, sqrtm1, secretKey[0])
  selectLop(t2, lopY, feOne, byte(secretKey[0] + 2))
  var lowOrderPoint: GePrecomp
  feAdd(lowOrderPoint.yp, t2, t1)
  feSub(lowOrderPoint.ym, t2, t1)
  feMul(lowOrderPoint.t2, t2, t1)
  feMul(lowOrderPoint.t2, lowOrderPoint.t2, D2)

  # add low order point to the public key
  geMadd(pk, pk, lowOrderPoint, t1, t2)

  # convert to Montgomery u coordinate (we ignore the sign)
  feAdd(t1, pk.z, pk.y)
  feSub(t2, pk.z, pk.y)
  feInvert(t2, t2)
  feMul(t1, t1, t2)
  feTobytes(cast[BytePtr](unsafeAddr result[0]), t1)

  wipe(t1)
  wipe(pk)
  wipe(t2)
  wipe(lowOrderPoint)
  wipe(scalar)

proc x25519ToEddsa*(x25519Key: array[32, byte]): array[32, byte] =
  ## Convert an X25519 public key to an EdDSA public key.
  ## The sign of x is assumed positive.
  var t1, t2: Fe
  feFrombytes(t2, cast[BytePtr](unsafeAddr x25519Key[0]))
  feSub(t1, t2, feOne)
  feAdd(t2, t2, feOne)
  feInvert(t2, t2)
  feMul(t1, t1, t2)
  feTobytes(cast[BytePtr](unsafeAddr result[0]), t1)
  wipe(t1)
  wipe(t2)

proc eddsaToX25519*(eddsaKey: array[32, byte]): array[32, byte] =
  ## Convert an EdDSA public key to an X25519 public key.
  ## The sign of x is ignored.
  var t1, t2: Fe
  feFrombytes(t2, cast[BytePtr](unsafeAddr eddsaKey[0]))
  feAdd(t1, feOne, t2)
  feSub(t2, feOne, t2)
  feInvert(t2, t2)
  feMul(t1, t1, t2)
  feTobytes(cast[BytePtr](unsafeAddr result[0]), t1)
  wipe(t1)
  wipe(t2)

{.pop.}
