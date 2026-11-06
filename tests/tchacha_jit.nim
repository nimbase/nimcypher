import std/unittest
import std/random

import nimcypher/algos/chacha20
import nimcypher/algos/internal/chacha_jit

# Differential: JIT rounds vs scalar. Runs with
# -d:features.nimcypher.nimdynasm on amd64.

suite "chacha jit vs scalar":
  test "random blocks agree":
    randomize(0xC4A0)
    for _ in 0 ..< 200:
      var inp: array[16, uint32]
      for i in 0 ..< 16:
        inp[i] = uint32(rand(int(high(uint32))))
      var o1, o2: array[16, uint32]
      chacha20RoundsScalar(o1, inp)
      chacha20RoundsJit(o2, inp)
      check o1 == o2

  test "edge blocks agree":
    for v in [0'u32, 1, 0xFFFFFFFF'u32, 0x80000000'u32]:
      var inp: array[16, uint32]
      for i in 0 ..< 16:
        inp[i] = v xor uint32(i * 0x9E3779B9)
      var o1, o2: array[16, uint32]
      chacha20RoundsScalar(o1, inp)
      chacha20RoundsJit(o2, inp)
      check o1 == o2

  test "two-block avx2 agrees":
    if cpuHasAvx2():
      randomize(0x2B1C)
      for _ in 0 ..< 60:
        var b0, b1: array[16, uint32]
        for i in 0 ..< 16:
          b0[i] = uint32(rand(high(int)))
          b1[i] = uint32(rand(high(int)))
        # interleave to din layout: word w of block k at
        # (w shr 2) shl 3 + (w and 3) + 4*k
        var din, poolJit: array[32, uint32]
        for w in 0 ..< 16:
          let aIdx = (w shr 2) shl 3 + (w and 3)
          din[aIdx] = b0[w]
          din[aIdx + 4] = b1[w]
        chacha20Rounds2Jit(poolJit, din)
        var e0, e1: array[16, uint32]
        chacha20RoundsScalar(e0, b0)
        chacha20RoundsScalar(e1, b1)
        for w in 0 ..< 16:
          let aIdx = (w shr 2) shl 3 + (w and 3)
          check poolJit[aIdx] == e0[w]
          check poolJit[aIdx + 4] == e1[w]
    else:
      skip()
