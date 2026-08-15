# Elligator 2: map representatives to curve points and back.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/options

import ./common
import ./internal/fe
import ./x25519
import ./chacha20

{.push checks: off.}

const
  A: Fe = [int32 486662, 0, 0, 0, 0, 0, 0, 0, 0, 0]

proc elligatorMap*(hidden: array[32, byte]): array[32, byte] =
  ## Map a 32-byte representative to a curve point (u coordinate).
  var r, u, t1, t2, t3: Fe
  feFrombytesMask(r, cast[BytePtr](unsafeAddr hidden[0]), 2)
  feSq(r, r)
  feAdd(t1, r, r)
  feAdd(u, t1, feOne)
  feSq(t2, u)
  feMul(t3, A2, t1)
  feSub(t3, t3, t2)
  feMul(t3, t3, A)
  feMul(t1, t2, u)
  feMul(t1, t3, t1)
  let isSquare = invsqrt(t1, t1)
  feMul(u, r, ufactor)
  feCcopy(u, feOne, isSquare)
  feSq(t1, t1)
  feMul(u, u, A)
  feMul(u, u, t3)
  feMul(u, u, t2)
  feMul(u, u, t1)
  feNeg(u, u)
  feTobytes(cast[BytePtr](unsafeAddr result[0]), u)
  wipe(t1)
  wipe(r)
  wipe(t2)
  wipe(u)
  wipe(t3)

proc elligatorRev*(curve: array[32, byte], tweak: byte):
    Option[array[32, byte]] =
  ## Map a curve point back to a representative, if possible.
  ## The tweak should be a random byte. Returns `none` if the point
  ## cannot be represented.
  var t1, t2, t3: Fe
  feFrombytes(t1, cast[BytePtr](unsafeAddr curve[0])) # t1 = u
  feAdd(t2, t1, A)                                    # t2 = u + A
  feMul(t3, t1, t2)
  feMulSmall(t3, t3, -2)
  let isSquare = invsqrt(t3, t3)
  if isSquare != 0:
    feCcopy(t1, t2, int(tweak and 1)) # multiply by u if v is positive,
    feMul(t3, t1, t3)                 # multiply by u+A otherwise
    feMulSmall(t1, t3, 2)
    feNeg(t2, t3)
    feCcopy(t3, t2, feIsOdd(t1))
    var hidden: array[32, byte]
    feTobytes(cast[BytePtr](unsafeAddr hidden[0]), t3)
    # pad with two random bits
    hidden[31] = hidden[31] or (tweak and 0xc0)
    result = some(hidden)
  wipe(t1)
  wipe(t2)
  wipe(t3)

proc toKeyArray(b: openArray[byte]): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = b[i]

proc elligatorKeyPair*(seed: array[32, byte]):
    (array[32, byte], array[32, byte]) =
  ## Generate an Elligator key pair from a seed.
  ## Returns (hidden representative, secret_key).
  var pk: array[32, byte]
  var buf: array[64, byte]
  for i in 0 ..< 32:
    buf[32 + i] = seed[i]
  var nonce: array[8, byte]
  while true:
    # buf = chacha20 stream (64 bytes) keyed by the current buf[32..63]
    var key: array[32, byte]
    for i in 0 ..< 32:
      key[i] = buf[32 + i]
    discard chacha20Djb(cast[BytePtr](unsafeAddr buf[0]), nil, 64,
                        key, nonce, 0)
    pk = x25519DirtyFast(toKeyArray(buf))
    let rep = elligatorRev(pk, buf[32])
    if rep.isSome:
      # store the representative into buf[32..63] (overlapping input)
      for i in 0 ..< 32:
        buf[32 + i] = rep.get[i]
      break
  for i in 0 ..< 32:
    result[0][i] = buf[32 + i]
    result[1][i] = buf[i]
  wipe(pk)
  wipe(buf)

{.pop.}
