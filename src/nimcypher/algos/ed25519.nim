# Ed25519 signatures (EdDSA with curve25519 + SHA-512).
#
# Ported from `monocypher-ed25519.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ./common
import ./sha512
import ./eddsa
import ./internal/edl

{.push checks: off.}

# "SigEd25519 no Ed25519 collisions" + a byte 1 + a NUL terminator
const
  domain: array[34, byte] = block:
    var d: array[34, byte]
    let s = "SigEd25519 no Ed25519 collisions\x01\x00"
    for i in 0 ..< 34:
      d[i] = byte(s[i])
    d

proc ed25519KeyPair*(seed: array[32, byte]): (array[64, byte], array[32, byte]) =
  ## Generate an Ed25519 key pair from a seed.
  ## Returns (secret_key, public_key).
  var a: array[64, byte]
  for i in 0 ..< 32:
    a[i] = seed[i]
    result[0][i] = seed[i]
  let ah = sha512(a.toOpenArray(0, 31))
  for i in 0 ..< 64:
    a[i] = ah[i]
  trimScalar(cast[BytePtr](unsafeAddr a[0]), cast[BytePtr](unsafeAddr a[0])) # trims in place
  result[1] = scalarbase(a.toOpenArray(0, 31))
  for i in 0 ..< 32:
    result[0][32 + i] = result[1][i]
  wipe(a)

proc hashReduce(h: var array[32, byte], a, b, c, d: openArray[byte]) =
  var ctx: Sha512Context
  init(ctx)
  update(ctx, a)
  update(ctx, b)
  update(ctx, c)
  update(ctx, d)
  h = reduce(final(ctx))

proc domSign(signature: var array[64, byte], secretKey: array[64, byte],
             dom: openArray[byte], message: openArray[byte]) =
  var a: array[64, byte] # secret scalar and prefix
  var r: array[32, byte] # secret deterministic "random" nonce
  var h: array[32, byte]
  var R: array[32, byte]
  let ah = sha512(secretKey.toOpenArray(0, 31))
  for i in 0 ..< 64:
    a[i] = ah[i]
  trimScalar(cast[BytePtr](unsafeAddr a[0]), cast[BytePtr](unsafeAddr a[0]))
  hashReduce(r, dom, a.toOpenArray(32, 63), message, [])
  R = scalarbase(r)
  hashReduce(h, dom, R, secretKey.toOpenArray(32, 63), message)
  for i in 0 ..< 32:
    signature[i] = R[i]
  let s = mulAdd(h, a.toOpenArray(0, 31), r)
  for i in 0 ..< 32:
    signature[32 + i] = s[i]
  wipe(a)
  wipe(r)

proc ed25519Sign*(message: openArray[byte], secretKey: array[64, byte]):
    array[64, byte] =
  ## Sign a message with an Ed25519 secret key.
  domSign(result, secretKey, [], message)

proc ed25519Check*(signature: array[64, byte], publicKey: array[32, byte],
                   message: openArray[byte]): bool =
  ## Verify an Ed25519 signature. Returns true if valid.
  var h: array[32, byte]
  hashReduce(h, signature.toOpenArray(0, 31), publicKey, message, [])
  result = checkEquation(signature, publicKey, h)

proc ed25519PhSign*(messageHash: array[64, byte], secretKey: array[64, byte]):
    array[64, byte] =
  ## Sign a pre-hashed message (Ed25519ph).
  domSign(result, secretKey, domain, messageHash)

proc ed25519PhCheck*(signature: array[64, byte], publicKey: array[32, byte],
                     messageHash: array[64, byte]): bool =
  ## Verify an Ed25519ph signature of a pre-hashed message.
  var h: array[32, byte]
  hashReduce(h, domain, signature.toOpenArray(0, 31), publicKey, messageHash)
  result = checkEquation(signature, publicKey, h)

{.pop.}
