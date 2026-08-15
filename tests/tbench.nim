# Benchmark suite: pure-Nim nimcypher port vs the real C Monocypher library.
#
# Every primitive is timed on identical inputs, once through the FFI bindings
# (C) and once through the pure-Nim implementation (Nim). The reported ratio
# is C-time / Nim-time: < 1 means the pure-Nim port is faster, > 1 means C is.
#
# Run with: nim c -r -d:danger --opt:speed tests/tbench.nim
# (or `nimble bench`).

import std/monotimes
import std/times
import std/strformat
import std/options

import nimcypher/algos/blake2b
import nimcypher/algos/sha512
import nimcypher/algos/chacha20
import nimcypher/algos/poly1305
import nimcypher/algos/aead
import nimcypher/algos/argon2
import nimcypher/algos/x25519
import nimcypher/algos/eddsa
import nimcypher/algos/ed25519
import nimcypher/algos/elligator

import monocypher_ffi

# Sink prevents the optimizer from eliminating benchmarked computations.
var sink: byte

proc timeIt(iterations: int, f: proc() {.closure.}): float =
  f() # warmup
  let start = getMonoTime()
  for _ in 0 ..< iterations:
    f()
  result = (getMonoTime() - start).inNanoseconds.float / 1e9

proc bench(label: string, iterations: int, c, n: proc() {.closure.}) =
  let ct = timeIt(iterations, c)
  let nt = timeIt(iterations, n)
  echo fmt"| {label} | {iterations} | {ct:.4f}s | {nt:.4f}s | {ct / nt:.2f}x |"

proc makeMsg(n: int): seq[byte] =
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = byte(i * 31 + 7)

proc benchBlake2b() =
  for size in [64, 1024, 65536]:
    let iters = if size == 64: 100_000
                elif size == 1024: 20_000
                else: 2_000
    let msg = makeMsg(size)
    var hashC: array[64, uint8]
    bench("blake2b " & $size & "B", iters,
      proc() =
        crypto_blake2b(addr hashC[0], 64, toPtr(msg), csize_t(msg.len))
        sink = sink xor hashC[0],
      proc() =
        let h = blake2b(msg)
        sink = sink xor h[0])

proc benchSha512() =
  for size in [64, 1024, 65536]:
    let iters = if size == 64: 50_000
                elif size == 1024: 20_000
                else: 1_000
    let msg = makeMsg(size)
    var hashC: array[64, uint8]
    bench("sha512 " & $size & "B", iters,
      proc() =
        crypto_sha512(addr hashC[0], toPtr(msg), csize_t(msg.len))
        sink = sink xor hashC[0],
      proc() =
        let h = sha512(msg)
        sink = sink xor h[0])

proc benchChacha20() =
  for size in [64, 1024, 65536]:
    let iters = if size == 64: 50_000
                elif size == 1024: 20_000
                else: 1_000
    let msg = makeMsg(size)
    var key: array[32, uint8]
    var nonce: array[8, uint8]
    for i in 0 ..< 32: key[i] = byte(i)
    var ctC = newSeq[uint8](size)
    bench("chacha20 " & $size & "B", iters,
      proc() =
        discard crypto_chacha20_djb(addr ctC[0], toPtr(msg), csize_t(msg.len),
                                    addr key[0], addr nonce[0], 0)
        sink = sink xor ctC[0],
      proc() =
        let c = chacha20(msg, key, nonce)
        sink = sink xor c[0])

proc benchPoly1305() =
  for size in [1024, 65536]:
    let iters = if size == 1024: 50_000 else: 2_000
    let msg = makeMsg(size)
    var key: array[32, uint8]
    for i in 0 ..< 32: key[i] = byte(i)
    var macC: array[16, uint8]
    bench("poly1305 " & $size & "B", iters,
      proc() =
        crypto_poly1305(macC, toPtr(msg), csize_t(msg.len), key)
        sink = sink xor macC[0],
      proc() =
        let m = poly1305(msg, key)
        sink = sink xor m[0])

proc benchAead() =
  for size in [1024, 65536]:
    let iters = if size == 1024: 10_000 else: 500
    let msg = makeMsg(size)
    var key: array[32, uint8]
    var nonce: array[24, uint8]
    for i in 0 ..< 32: key[i] = byte(i)
    for i in 0 ..< 24: nonce[i] = byte(100 + i)
    var ctC = newSeq[uint8](size)
    var ptC = newSeq[uint8](size)
    var macC: array[16, uint8]
    bench("aead lock+unlock " & $size & "B", iters,
      proc() =
        crypto_aead_lock(addr ctC[0], addr macC[0], addr key[0], addr nonce[0],
                         nil, 0, toPtr(msg), csize_t(msg.len))
        discard crypto_aead_unlock(addr ptC[0], addr macC[0], addr key[0],
                                   addr nonce[0], nil, 0,
                                   addr ctC[0], csize_t(msg.len))
        sink = sink xor ctC[0],
      proc() =
        let (c, t) = aeadLock(key, nonce, msg)
        discard aeadUnlock(key, nonce, c, t)
        sink = sink xor c[0])

proc benchX25519() =
  var skA: array[32, uint8]
  var pkA: array[32, uint8]
  for i in 0 ..< 32: skA[i] = byte(i)
  crypto_x25519_public_key(addr pkA[0], addr skA[0])
  var outC: array[32, uint8]
  bench("x25519", 2_000,
    proc() =
      crypto_x25519(addr outC[0], addr skA[0], addr pkA[0])
      sink = sink xor outC[0],
    proc() =
      let s = x25519(skA, pkA)
      sink = sink xor s[0])

proc benchSignatures() =
  var seed: array[32, uint8]
  for i in 0 ..< 32: seed[i] = byte(i)
  # C key pairs (they wipe the seed)
  var skE: array[64, uint8]
  var pkE: array[32, uint8]
  var seedC = seed
  crypto_eddsa_key_pair(addr skE[0], addr pkE[0], addr seedC[0])
  var sk25519: array[64, uint8]
  var pk25519: array[32, uint8]
  var seedC2 = seed
  crypto_ed25519_key_pair(addr sk25519[0], addr pk25519[0], addr seedC2[0])
  # Nim key pairs from the untouched seed
  let (skEN, pkEN) = eddsaKeyPair(seed)
  let (sk25519N, pk25519N) = ed25519KeyPair(seed)

  let msg = makeMsg(1024)

  # EdDSA (BLAKE2b)
  var sigC: array[64, uint8]
  bench("eddsa sign 1KB", 1_000,
    proc() =
      crypto_eddsa_sign(addr sigC[0], addr skE[0], toPtr(msg), csize_t(msg.len))
      sink = sink xor sigC[0],
    proc() =
      let s = eddsaSign(msg, skEN)
      sink = sink xor s[0])
  crypto_eddsa_sign(addr sigC[0], addr skE[0], toPtr(msg), csize_t(msg.len))
  let sigEN = eddsaSign(msg, skEN)
  bench("eddsa check 1KB", 1_000,
    proc() =
      discard crypto_eddsa_check(addr sigC[0], addr pkE[0], toPtr(msg),
                                 csize_t(msg.len))
      sink = sink xor sigC[0],
    proc() =
      discard eddsaCheck(sigEN, pkEN, msg)
      sink = sink xor sigEN[0])

  # Ed25519 (SHA-512)
  var sig25519C: array[64, uint8]
  bench("ed25519 sign 1KB", 1_000,
    proc() =
      crypto_ed25519_sign(addr sig25519C[0], addr sk25519[0], toPtr(msg),
                          csize_t(msg.len))
      sink = sink xor sig25519C[0],
    proc() =
      let s = ed25519Sign(msg, sk25519N)
      sink = sink xor s[0])
  crypto_ed25519_sign(addr sig25519C[0], addr sk25519[0], toPtr(msg),
                      csize_t(msg.len))
  let sig25519N = ed25519Sign(msg, sk25519N)
  bench("ed25519 check 1KB", 1_000,
    proc() =
      discard crypto_ed25519_check(addr sig25519C[0], addr pk25519[0],
                                   toPtr(msg), csize_t(msg.len))
      sink = sink xor sig25519C[0],
    proc() =
      discard ed25519Check(sig25519N, pk25519N, msg)
      sink = sink xor sig25519N[0])

proc benchElligator() =
  var hidden: array[32, uint8]
  for i in 0 ..< 32: hidden[i] = byte(i * 11 + 1)
  var curveC: array[32, uint8]
  bench("elligator map", 3_000,
    proc() =
      crypto_elligator_map(curveC, hidden)
      sink = sink xor curveC[0],
    proc() =
      let c = elligatorMap(hidden)
      sink = sink xor c[0])
  crypto_elligator_map(curveC, hidden)
  var repC: array[32, uint8]
  bench("elligator rev", 3_000,
    proc() =
      discard crypto_elligator_rev(repC, curveC, 0x42'u8)
      sink = sink xor repC[0],
    proc() =
      let r = elligatorRev(curveC, 0x42'u8)
      if r.isSome:
        sink = sink xor r.get[0])

proc benchArgon2() =
  var pass = @[byte(0x70), byte(0x61), byte(0x73), byte(0x73)]
  var salt: seq[byte]
  for i in 0 ..< 16: salt.add(byte(i))
  var config = crypto_argon2_config(algorithm: uint32(CRYPTO_ARGON2_I),
                                    nb_blocks: 8, nb_passes: 1, nb_lanes: 1)
  var inputs = crypto_argon2_inputs(pass: toPtr(pass), salt: toPtr(salt),
                                    pass_size: uint32(pass.len),
                                    salt_size: uint32(salt.len))
  var work = newSeq[uint8](8 * 1024)
  var hashC: array[32, uint8]
  var cfgN = Argon2Config(algorithm: Argon2Algorithm.i,
                          nbBlocks: 8, nbPasses: 1, nbLanes: 1)
  bench("argon2i 8blk 1pass", 20,
    proc() =
      crypto_argon2(addr hashC[0], 32, cast[pointer](addr work[0]),
                    config, inputs, crypto_argon2_no_extras)
      sink = sink xor hashC[0],
    proc() =
      let h = argon2(cfgN, 32, pass, salt)
      sink = sink xor h[0])

when isMainModule:
  echo "Benchmark: pure-Nim NimCypher vs C Monocypher"
  echo "Ratio = Monocypher time / NimCypher time (< 1 means NimCypher slower, > 1 means NimCypher faster)"
  echo ""
  echo "| operation | iters | Monocypher | NimCypher | M/N |"
  echo "| --- | ---: | ---: | ---: | ---: |"
  benchBlake2b()
  benchSha512()
  benchChacha20()
  benchPoly1305()
  benchAead()
  benchX25519()
  benchSignatures()
  benchElligator()
  benchArgon2()
  echo "checksum (prevents dead-code elimination): ", sink
