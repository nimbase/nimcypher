# Package

version       = "0.3.0"
author        = "George Lemon"
description   = "A pure-Nim port of Monocypher 4.0.3: a small, easy to use crypto library."
license       = "BSD-2-Clause"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.10"
requires "bigints >= 1.0.0"

# Optional SIMD acceleration (ChaCha20, AES-NI, PCLMULQDQ): activate with
# `nimble --features:nimsimd install` or from a consumer via
# `requires "nimcypher >= 0.1.0[nimsimd]"`. When active, Nimble installs
# nimsimd and defines `features.nimcypher.nimsimd` for the build.
feature "nimsimd":
  requires "nimsimd"

# task test, "Run the test suite":
#   for t in ["tcommon", "tchacha20", "tpoly1305", "tblake2b", "taead",
#             "tx25519", "teddsa", "telligator", "targon2", "tsha512",
#             "tsha1", "tsha256", "tsha224", "tsha384", "tsha512t", "tmd5", "txxhash", "tbigint_ext", "thkdf", "ted25519",
#             "tmontgomery", "trsa", "tecdsa", "tinterop", "thighlevel", "taes", "tgcm",
#             "topenssl", "trc4", "ttls_codec", "ttls_key_schedule",
#             "ttls_aead", "ttls_record", "ttls_handshake",
#             "ttls_asn1", "ttls_x509", "ttls_verify", "ttls_client",
#             "ttls_interop", "ttls_keys", "ttls_loopback"]:
#     exec "nim c -r --hints:off -d:danger tests/" & t & ".nim"

task test_simd, "Run the SIMD-accelerated tests":
  exec "nimble install -y nimsimd"
  for t in ["tchacha20", "taead", "tblake2b", "tinterop", "taes", "tgcm",
            "tmontgomery", "trsa"]:
    exec "nim c -r --hints:off -d:danger " &
         "-d:features.nimcypher.nimsimd tests/" & t & ".nim"

task bench, "Benchmark NimCypher (scalar vs SIMD) against C Monocypher and nimcrypto":
  exec "nimble install -y nimsimd nimcrypto"
  exec "nim c -r --hints:off -d:danger --opt:speed --mm:arc " &
       "-d:features.nimcypher.nimsimd tests/bench.nim"
