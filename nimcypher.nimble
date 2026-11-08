# Package

version       = "0.4.0"
author        = "George Lemon"
description   = "A pure-Nim port of Monocypher 4.0.3: a small, easy to use crypto library."
license       = "BSD-2-Clause"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.10"
requires "bigints >= 1.0.0"
# JIT backend (replaces nimsimd). Resolved in develop mode to the local
# dynasm checkout via clue.lock; all JIT code paths stay gated behind
# `-d:features.nimcypher.nimdynasm` (off by default), so this does not
# change default builds.
requires "dynasm >= 0.1.0"

# Optional SIMD acceleration (ChaCha20, AES-NI, PCLMULQDQ): activate with
# `clue install --features:nimsimd --depsOnly` or from a consumer via
# `requires "nimcypher >= 0.1.0[nimsimd]"`. When active, clue installs
# nimsimd and defines `features.nimcypher.nimsimd` for the build.
feature "nimsimd":
  requires "nimsimd"

# Optional dynasm JIT backend (replaces nimsimd): compile with
# `clue build --features:nimdynasm` (or `clue test --features:nimdynasm`).
# dynasm resolves in develop mode (local checkout carrying the P0-P3
# encoder sets) via clue.lock; keep `requires "dynasm >= 0.1.0"` above
# in sync. All JIT code stays gated behind the define (off by default).
feature "nimdynasm":
  requires "dynasm >= 0.1.0"

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
            "topenssl_aead", "tmontgomery", "trsa"]:
    exec "nim c -r --hints:off -d:danger " &
         "-d:features.nimcypher.nimsimd tests/" & t & ".nim"

task test_jit, "Run the dynasm JIT differential tests":
  ## AES/ChaCha/Blake2b/GHASH/MULX batch kernels plus the fused-GCM
  ## and dispatch integration suites, all against their scalar
  ## references. Needs a dynasm with the x64 encoders + detectors
  ## (the jit/simd-isa branch, merged to main);
  ## suites self-skip where the host arch lacks a backend.
  for t in ["taes_jit", "tchacha_jit", "tblake2b_jit", "tghash_jit",
            "tmulwide_jit", "tgcm_fused", "topenssl_aead", "taes", "tgcm"]:
    exec "nim c -r --hints:off -d:danger " &
         "-d:features.nimcypher.nimdynasm tests/" & t & ".nim"

task bench, "Benchmark NimCypher (scalar vs SIMD) against C Monocypher and nimcrypto":
  exec "nimble install -y nimsimd nimcrypto"
  exec "nim c -r --hints:off -d:danger --opt:speed --mm:arc " &
       "-d:features.nimcypher.nimsimd tests/bench.nim"

task bench_tls, "Benchmark TLS handshakes + records: nimcypher vs OpenSSL":
  exec "nim c -r --hints:off -d:ssl -d:danger --opt:speed " &
       "--threads:on --mm:arc tests/bench_tls.nim"

task bench_tls_simd, "Benchmark TLS with SIMD acceleration (AES-NI, AVX2, MULX)":
  exec "nimble install -y nimsimd"
  exec "nim c -r --hints:off -d:ssl -d:danger --opt:speed " &
       "--threads:on --mm:arc " &
       "-d:features.nimcypher.nimsimd tests/bench_tls.nim"
