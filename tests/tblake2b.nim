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

when defined(features.nimcypher.nimsimd):
  test "blake2b parallel == scalar per message":
    var msgs: array[4, seq[byte]]
    var seed = 1
    for k in 0 ..< 4:
      let n = [0, 1, 127, 128, 129, 255, 256, 257, 1000, 4096][k * 2 + 1]
      for j in 0 ..< n:
        seed = seed * 1103515245 + 12345
        msgs[k].add(byte((seed shr 16) and 0xff))
    let out4 = blake2bParallel(msgs)
    for k in 0 ..< 4:
      check out4[k] == blake2b(msgs[k], 64)
    # a single long message alongside short/empty ones
    var msgs2: array[4, seq[byte]]
    for j in 0 ..< 3000:
      seed = seed * 1103515245 + 12345
      msgs2[1].add(byte((seed shr 16) and 0xff))
    let out2 = blake2bParallel(msgs2, 32)
    for k in 0 ..< 4:
      check out2[k] == blake2b(msgs2[k], 32)
