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
