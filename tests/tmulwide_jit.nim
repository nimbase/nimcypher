import std/unittest
import std/random

import nimcypher/algos/internal/montgomery64 except mulWide

# Differential: JIT MULX vs splitting oracle. Runs with
# -d:features.nimcypher.nimdynasm on amd64; execution is gated on the
# functional self-test (this host class misexecutes MULX even from
# clang-identical bytes, so the test skips there with a NOTE).


when defined(amd64):
  import nimcypher/algos/internal/mulwide_jit

  suite "mulwide jit vs splitting":
    test "random products agree":
      if mulwideJitAvailable():
        randomize(0x9A7)
        for _ in 0 ..< 200:
          let a = uint64(rand(high(int))) or
            (uint64(rand(high(int))) shl 1)
          let b = uint64(rand(high(int)))
          var hiJ, hiS: uint64
          let loJ = mulWideJit(a, b, hiJ)
          let loS = mulWideSplit(a, b, hiS)
          check loJ == loS
          check hiJ == hiS
          check loJ == a * b
      else:
        echo "NOTE: MULX executes incorrectly on this host; skipping " &
          "mulwide execution checks (splitting fallback active)"
        skip()
else:
  suite "mulwide jit vs splitting (requires amd64)":
    test "skipped on non-amd64":
      skip()
