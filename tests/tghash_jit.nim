import std/unittest
import std/random

import nimcypher/algos/gcm except ghashFold
import nimcypher/algos/internal/ghash_jit
import nimcypher/algos/common

# Differential: JIT fold vs scalar reference. Runs only with
# -d:features.nimcypher.nimdynasm on amd64 (the module errors out
# otherwise, mirroring ghash_simd's arch gate).

suite "ghash jit vs scalar":
  test "random blocks agree":
    randomize(0x6A45)
    for _ in 0 ..< 200:
      var acc, h, blk: array[16, byte]
      for i in 0 ..< 16:
        acc[i] = byte(rand(255))
        h[i] = byte(rand(255))
        blk[i] = byte(rand(255))
      var a1 = acc
      var a2 = acc
      ghashFoldScalar(a1, h, cast[BytePtr](addr blk[0]))
      ghashFoldJit(a2, h, cast[BytePtr](addr blk[0]))
      check a1 == a2

  test "edge blocks agree":
    var acc: array[16, byte]
    var h: array[16, byte]
    var blk: array[16, byte]
    for v in [0'u8, 1, 0x80, 0xFF]:
      for i in 0 ..< 16:
        acc[i] = v
        h[i] = byte(255 - int(v))
        blk[i] = v
      var a1 = acc
      var a2 = acc
      ghashFoldScalar(a1, h, cast[BytePtr](addr blk[0]))
      ghashFoldJit(a2, h, cast[BytePtr](addr blk[0]))
      check a1 == a2
