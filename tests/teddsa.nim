import std/unittest

import nimcypher/algos/eddsa

import vectorutils
import vectors

test "edDSA sign vectors":
  var i = 0
  while i < edDSAVectors.len:
    let secretK = hexToBytes(edDSAVectors[i]); inc i
    let publicK = hexToBytes(edDSAVectors[i]); inc i
    let msg = hexToBytes(edDSAVectors[i]); inc i
    let expected = hexToBytes(edDSAVectors[i]); inc i
    var sk: array[64, byte]
    for j in 0 ..< 32:
      sk[j] = secretK[j]
    for j in 0 ..< 32:
      sk[32 + j] = publicK[j]
    let sig = eddsaSign(msg, sk)
    check sig == expected

test "edDSA key pair vectors":
  var i = 0
  while i < edDSAPkVectors.len:
    let seed = hexToBytes(edDSAPkVectors[i]); inc i
    let expected = hexToBytes(edDSAPkVectors[i]); inc i
    let (sk, pk) = eddsaKeyPair(toArray[32](seed))
    check pk == expected
    # secret key bundles seed then public key
    check sk[0 ..< 32] == seed
    check sk[32 ..^ 1] == expected

test "edDSA roundtrip + forgeries rejected":
  var seed: array[32, byte]
  for j in 0 ..< 32: seed[j] = byte(j * 3)
  var msg: seq[byte]
  for j in 0 ..< 30: msg.add(byte(200 - j))
  let (sk, pk) = eddsaKeyPair(seed)
  let sig = eddsaSign(msg, sk)
  check eddsaCheck(sig, pk, msg)
  # reject all-zero signature
  var zero: array[64, byte]
  check not eddsaCheck(zero, pk, msg)
  # reject each byte-flipped forgery
  for j in 0 ..< 64:
    var forgery = sig
    forgery[j] = byte(int(forgery[j]) + 1)
    check not eddsaCheck(forgery, pk, msg)

test "edDSA scalarbase equivalence":
  # Adding 8*L to a scalar yields the same point.
  const L: array[32, byte] = [
    byte 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  ]
  var scalar: array[32, byte]
  for j in 0 ..< 32: scalar[j] = byte(j * 7 + 1)
  scalar[31] = scalar[31] and 0xf
  # scalar_plus = scalar + 8*L
  var scalarPlus: array[32, byte]
  var acc = 0
  for i in 0 ..< 32:
    acc += int(scalar[i]) + int(L[i]) * 8
    scalarPlus[i] = byte(acc and 0xff)
    acc = acc shr 8
  let p1 = scalarbase(scalar)
  let p2 = scalarbase(scalarPlus)
  check p1 == p2
