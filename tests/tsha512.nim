import std/unittest

import nimcypher/algos/sha512

import vectorutils
import vectors

test "sha512 vectors":
  var i = 0
  while i < sha512Vectors.len:
    let input = hexToBytes(sha512Vectors[i]); inc i
    let expected = hexToBytes(sha512Vectors[i]); inc i
    let got = sha512(input)
    check got == expected

test "sha512_hmac vectors":
  var i = 0
  while i < sha512HmacVectors.len:
    let key = hexToBytes(sha512HmacVectors[i]); inc i
    let msg = hexToBytes(sha512HmacVectors[i]); inc i
    let expected = hexToBytes(sha512HmacVectors[i]); inc i
    let got = sha512Hmac(key, msg)
    check got == expected

test "sha512 incremental == one-shot":
  var input: seq[byte]
  for j in 0 ..< 200:
    input.add(byte(j * 3))
  let whole = sha512(input)
  var ctx: Sha512Context
  init(ctx)
  update(ctx, input[0 ..< 64])
  update(ctx, input[64 ..< 128])
  update(ctx, input[128 ..^ 1])
  let chunked = final(ctx)
  check chunked == whole

test "hmac incremental == one-shot":
  var key: seq[byte]
  for j in 0 ..< 32:
    key.add(byte(j + 1))
  var input: seq[byte]
  for j in 0 ..< 100:
    input.add(byte(j * 5))
  let whole = sha512Hmac(key, input)
  var ctx: Sha512HmacContext
  initHmac(ctx, key)
  update(ctx, input[0 ..< 40])
  update(ctx, input[40 ..^ 1])
  let chunked = final(ctx)
  check chunked == whole

test "hmac with empty key equals a zero-padded key":
  var input: seq[byte]
  for j in 0 ..< 16:
    input.add(byte(j))
  let emptyKey = sha512Hmac(newSeq[byte](0), input)
  let zeroKey = sha512Hmac(newSeq[byte](128), input) # padded to the block size
  check emptyKey == zeroKey
  check emptyKey.len == 64
