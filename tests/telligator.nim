import std/unittest
import std/options

import nimcypher/algos/elligator
import nimcypher/algos/x25519

import vectorutils
import vectors

test "elligator direct vectors":
  var i = 0
  while i < elligatorDirVectors.len:
    let hidden = hexToBytes(elligatorDirVectors[i]); inc i
    let expected = hexToBytes(elligatorDirVectors[i]); inc i
    let curve = elligatorMap(toArray[32](hidden))
    check curve == expected

test "elligator inverse vectors":
  var i = 0
  while i < elligatorInvVectors.len:
    let point = hexToBytes(elligatorInvVectors[i]); inc i
    let tweak = hexToBytes(elligatorInvVectors[i]); inc i
    let failure = hexToBytes(elligatorInvVectors[i]); inc i
    let expected = hexToBytes(elligatorInvVectors[i]); inc i
    let got = elligatorRev(toArray[32](point), tweak[0])
    if failure[0] != 0:
      check got.isNone
    else:
      check got.isSome
      check got.get == expected

test "elligator map/rev round trip":
  var hidden: array[32, byte]
  for j in 0 ..< 32: hidden[j] = byte(j * 11 + 3)
  hidden[31] = (hidden[31] and 0x3f) or 0x40
  let curve = elligatorMap(hidden)
  let back = elligatorRev(curve, 0x00)
  check back.isSome
  # map(rev(point)) must give back the point
  check elligatorMap(back.get) == curve

test "elligator x25519 compatibility":
  # Dirty and safe keys are compatible: X25519 gives the same shared
  # secret whether computed from the dirty public key or its representative.
  var sk1: array[32, byte]
  for j in 0 ..< 32: sk1[j] = byte(j * 5 + 2)
  var tweak = 0x42'u8
  var r: Option[array[32, byte]]
  var pkf: array[32, byte]
  var attempts = 0
  while true:
    attempts += 1
    check attempts <= 256
    pkf = x25519DirtyFast(sk1)
    r = elligatorRev(pkf, tweak)
    if r.isSome:
      break
    inc sk1[0]
  let pkr = elligatorMap(r.get)
  check pkr == pkf
  # both give the same shared secret
  var sk2: array[32, byte]
  for j in 0 ..< 32: sk2[j] = byte(150 - j)
  let e1 = x25519(sk2, pkf)
  let e2 = x25519(sk2, pkr)
  check e1 == e2

test "elligator key pair":
  var seed: array[32, byte]
  for j in 0 ..< 32: seed[j] = byte(j * 7 + 1)
  let (hidden, sk1) = elligatorKeyPair(seed)
  let pkr = elligatorMap(hidden)
  let pk1 = x25519PublicKey(sk1)
  var sk2: array[32, byte]
  for j in 0 ..< 32: sk2[j] = byte(120 - j)
  let e1 = x25519(sk2, pk1)
  let e2 = x25519(sk2, pkr)
  check e1 == e2
