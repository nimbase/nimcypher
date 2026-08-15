import std/unittest

import nimcypher/algos/ed25519
import nimcypher/algos/sha512

import vectorutils
import vectors

test "ed25519 sign vectors":
  var i = 0
  while i < ed25519Vectors.len:
    let secretK = hexToBytes(ed25519Vectors[i]); inc i
    let publicK = hexToBytes(ed25519Vectors[i]); inc i
    let msg = hexToBytes(ed25519Vectors[i]); inc i
    let expected = hexToBytes(ed25519Vectors[i]); inc i
    var sk: array[64, byte]
    for j in 0 ..< 32: sk[j] = secretK[j]
    for j in 0 ..< 32: sk[32 + j] = publicK[j]
    let sig = ed25519Sign(msg, sk)
    check sig == expected

test "ed25519 key pair vectors":
  var i = 0
  while i < ed25519PkVectors.len:
    let seed = hexToBytes(ed25519PkVectors[i]); inc i
    let expected = hexToBytes(ed25519PkVectors[i]); inc i
    let (sk, pk) = ed25519KeyPair(toArray[32](seed))
    check pk == expected
    check sk[0 ..< 32] == seed
    check sk[32 ..^ 1] == expected

test "ed25519 check vectors":
  var i = 0
  while i < ed25519CheckVectors.len:
    let publicK = hexToBytes(ed25519CheckVectors[i]); inc i
    let msg = hexToBytes(ed25519CheckVectors[i]); inc i
    let sig = hexToBytes(ed25519CheckVectors[i]); inc i
    let expected = hexToBytes(ed25519CheckVectors[i]); inc i
    let ok = ed25519Check(toArray[64](sig), toArray[32](publicK), msg)
    # out.buf[0] = check result: 0 if valid, -1 (0xff) if invalid
    check ok == (expected[0] == 0)

test "ed25519 roundtrip + forgeries rejected":
  var seed: array[32, byte]
  for j in 0 ..< 32: seed[j] = byte(j * 13)
  var msg: seq[byte]
  for j in 0 ..< 100: msg.add(byte(j * 7))
  let (sk, pk) = ed25519KeyPair(seed)
  let sig = ed25519Sign(msg, sk)
  check ed25519Check(sig, pk, msg)
  for j in 0 ..< 64:
    var forgery = sig
    forgery[j] = byte(int(forgery[j]) + 1)
    check not ed25519Check(forgery, pk, msg)

test "ed25519ph vectors + roundtrip":
  var i = 0
  while i < ed25519PhVectors.len:
    let skv = hexToBytes(ed25519PhVectors[i]); inc i
    let pkv = hexToBytes(ed25519PhVectors[i]); inc i
    let msg = hexToBytes(ed25519PhVectors[i]); inc i
    let expected = hexToBytes(ed25519PhVectors[i]); inc i
    var sk: array[64, byte]
    for j in 0 ..< 32: sk[j] = skv[j]
    for j in 0 ..< 32: sk[32 + j] = pkv[j]
    # generate the digest, then ph-sign
    let digest = sha512(msg)
    let sig = ed25519PhSign(digest, sk)
    check sig == expected
    check ed25519PhCheck(sig, toArray[32](pkv), digest)
