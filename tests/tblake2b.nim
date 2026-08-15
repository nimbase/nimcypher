import std/unittest

import nimcypher/algos/blake2b

import vectorutils
import vectors

test "blake2b vectors":
  var i = 0
  while i < blake2bVectors.len:
    let msg = hexToBytes(blake2bVectors[i]); inc i
    let key = hexToBytes(blake2bVectors[i]); inc i
    let expected = hexToBytes(blake2bVectors[i]); inc i
    let hash = keyedBlake2b(msg, key, expected.len)
    check hash == expected

test "blake2b incremental == one-shot":
  var input: seq[byte]
  for j in 0 ..< 256:
    input.add(byte(j * 7))
  let whole = blake2b(input)
  var ctx: Blake2bContext
  init(ctx, 64)
  for j in 0 ..< input.len:
    update(ctx, @[input[j]])
  let chunked = final(ctx)
  check chunked == whole

test "blake2b keyed incremental == one-shot":
  var key: seq[byte]
  for j in 0 ..< 32:
    key.add(byte(j))
  var input: seq[byte]
  for j in 0 ..< 100:
    input.add(byte(j * 3))
  let whole = keyedBlake2b(input, key)
  var ctx: Blake2bContext
  init(ctx, 64, key)
  update(ctx, input)
  let chunked = final(ctx)
  check chunked == whole
