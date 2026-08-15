import std/unittest

import nimcypher/algos/x25519

import vectorutils
import vectors

test "x25519 vectors":
  var i = 0
  while i < x25519Vectors.len:
    let scalar = hexToBytes(x25519Vectors[i]); inc i
    let point = hexToBytes(x25519Vectors[i]); inc i
    let expected = hexToBytes(x25519Vectors[i]); inc i
    let got = x25519(toArray[32](scalar), toArray[32](point))
    check got == expected

test "x25519_pk vectors":
  var i = 0
  while i < x25519PkVectors.len:
    let sk = hexToBytes(x25519PkVectors[i]); inc i
    let expected = hexToBytes(x25519PkVectors[i]); inc i
    let got = x25519PublicKey(toArray[32](sk))
    check got == expected

test "x25519 known ladder 1 and 1K":
  const
    one = [byte 0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
           0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
           0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
           0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79]
    oneK = [byte 0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
            0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
            0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
            0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51]
  var k: array[32, byte]
  k[0] = 9
  var u: array[32, byte]
  u[0] = 9
  k = x25519PublicKey(k)
  check k == one
  for i in 1 ..< 1000:
    let tmp = x25519(k, u)
    u = k
    k = tmp
  check k == oneK

test "x25519 inverse round trip":
  var b: array[32, byte]
  for i in 0 ..< 32: b[i] = byte(i + 3)
  let base = x25519PublicKey(b) # random point (cofactor cleared)
  var sk: array[32, byte]
  for i in 0 ..< 32: sk[i] = byte(200 - i)
  let pk = x25519(sk, base)
  let blind = x25519Inverse(sk, pk)
  check blind == base

test "x25519 conversions round trip":
  var seed: array[32, byte]
  for i in 0 ..< 32: seed[i] = byte(i * 5)
  # eddsa_to_x25519 then x25519_to_eddsa
  let xpk = eddsaToX25519(seed)
  let epk = x25519ToEddsa(xpk)
  # x coordinate always positive, y coordinate back to original
  check (epk[31] and 0x80) == 0
  var adjusted = seed
  adjusted[31] = adjusted[31] and 0x7f
  check epk == adjusted

test "x25519 dirty == clean with cleared low bits":
  var sk1: array[32, byte]
  for i in 0 ..< 32: sk1[i] = byte(i * 7)
  let pks = x25519DirtySmall(sk1)
  let pkf = x25519DirtyFast(sk1)
  # both dirty functions behave the same
  check pks == pkf
  var skc = sk1
  skc[0] = skc[0] and 248
  let pk1 = x25519PublicKey(skc)
  check x25519DirtySmall(skc) == pk1
  check x25519DirtyFast(skc) == pk1
