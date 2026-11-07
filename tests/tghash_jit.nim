import std/unittest
import std/random

import nimcypher/algos/gcm except ghashFold
import nimcypher/algos/common

# Differential: JIT fold vs scalar reference. Runs only with
# -d:features.nimcypher.nimdynasm on amd64 (the module errors out
# otherwise, mirroring ghash_simd's arch gate).


when defined(features.nimcypher.nimdynasm) and
    (defined(amd64)):
  import nimcypher/algos/internal/ghash_jit

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

    test "agg8 equals serial folds":
      discard ghashAgg8JitAvailable()
      randomize(0xA668)
      for _ in 0 ..< 60:
        var acc, h: array[16, byte]
        for i in 0 ..< 16:
          acc[i] = byte(rand(255))
          h[i] = byte(rand(255))
        var rawPow: array[8, array[16, byte]]
        rawPow[0] = h
        for i in 1 ..< 8:
          var z: array[16, byte]
          ghashFoldScalar(z, h, cast[BytePtr](addr rawPow[i - 1][0]))
          rawPow[i] = z
        var hpow: array[ghashPowSlots, array[16, byte]]
        buildGhashPowers(hpow, rawPow)
        var blks: array[8, array[16, byte]]
        for b in 0 ..< 8:
          for i in 0 ..< 16:
            blks[b][i] = byte(rand(255))
        var e = acc
        for b in 0 ..< 8:
          ghashFoldScalar(e, h, cast[BytePtr](addr blks[b][0]))
        var g = acc
        ghashAgg8Jit(g, cast[BytePtr](addr hpow[0]),
                     cast[BytePtr](addr blks[0]))
        check e == g
      for v in [0'u8, 0xFF]:
        var acc, h: array[16, byte]
        for i in 0 ..< 16:
          acc[i] = v
          h[i] = v
        var rawPow: array[8, array[16, byte]]
        rawPow[0] = h
        for i in 1 ..< 8:
          var z: array[16, byte]
          ghashFoldScalar(z, h, cast[BytePtr](addr rawPow[i - 1][0]))
          rawPow[i] = z
        var hpow: array[ghashPowSlots, array[16, byte]]
        buildGhashPowers(hpow, rawPow)
        var blks: array[8, array[16, byte]]
        for b in 0 ..< 8:
          for i in 0 ..< 16:
            blks[b][i] = byte(b xor int(v))
        var e = acc
        for b in 0 ..< 8:
          ghashFoldScalar(e, h, cast[BytePtr](addr blks[b][0]))
        var g = acc
        ghashAgg8Jit(g, cast[BytePtr](addr hpow[0]),
                     cast[BytePtr](addr blks[0]))
        check e == g
else:
  suite "ghash jit vs scalar (requires nimdynasm)":
    test "skipped (no JIT)":
      skip()
