# Package

version       = "0.2.2"
author        = "George Lemon"
description   = "A pure-Nim port of Monocypher 4.0.3: a small, easy to use crypto library."
license       = "BSD-2-Clause OR CC0-1.0"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.10"

# Optional SIMD acceleration (ChaCha20, AES-NI, PCLMULQDQ): activate with
# `nimble --features:nimsimd install` or from a consumer via
# `requires "nimcypher >= 0.1.0[nimsimd]"`. When active, Nimble installs
# nimsimd and defines `features.nimcypher.nimsimd` for the build.
feature "nimsimd":
  requires "nimsimd"

task test, "Run the test suite":
  for t in ["tcommon", "tchacha20", "tpoly1305", "tblake2b", "taead",
            "tx25519", "teddsa", "telligator", "targon2", "tsha512",
            "tsha1", "tsha256", "thkdf", "ted25519", "tinterop", "thighlevel", "taes", "tgcm"]:
    exec "nim c -r --hints:off -d:danger -d:e2eeFastTests tests/" & t & ".nim"

task test_simd, "Run the SIMD-accelerated tests":
  exec "nimble install -y nimsimd"
  for t in ["tchacha20", "taead", "tblake2b", "tinterop", "taes", "tgcm"]:
    exec "nim c -r --hints:off -d:danger -d:e2eeFastTests " &
         "-d:features.nimcypher.nimsimd tests/" & t & ".nim"

task bench, "Benchmark NimCypher (scalar vs SIMD) against C Monocypher and nimcrypto":
  exec "nimble install -y nimsimd nimcrypto"
  exec "nim c -r --hints:off -d:danger --opt:speed --mm:arc " &
       "-d:features.nimcypher.nimsimd tests/bench.nim"
