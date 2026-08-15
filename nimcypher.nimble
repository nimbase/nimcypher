# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "A pure-Nim port of Monocypher 4.0.3: a small, easy to use crypto library."
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.10"

task test, "Run the test suite":
  for t in ["tcommon", "tchacha20", "tpoly1305", "tblake2b", "taead",
            "tx25519", "teddsa", "telligator", "targon2", "tsha512",
            "thkdf", "ted25519", "tinterop", "thighlevel"]:
    exec "nim c -r --hints:off -d:danger -d:e2eeFastTests tests/" & t & ".nim"

task bench, "Benchmark the pure-Nim port against the C Monocypher library":
  exec "nim c -r --hints:off -d:danger --opt:speed --mm:arc tests/tbench.nim"