# Benchmark suite: pure-Nim nimcypher port vs the real C Monocypher library.
#
# Every primitive is timed on identical inputs, once through the FFI bindings
# (C) and once through the pure-Nim implementation. When the library is built
# with SIMD acceleration (see `nimble bench`, which passes
# -d:features.nimcypher.nimsimd), the "NimCypher+SIMD" column reflects the
# accelerated kernels while "NimCypher" shows the scalar reference. The
# reported ratios are C-time / Nim-time: < 1 means NimCypher is faster,
# > 1 means C is.
#
# Run with: nimble bench   (SIMD comparison)
#           nim c -r -d:danger --opt:speed tests/tbench.nim   (scalar only)

import std/monotimes
import std/times
import std/strformat
import std/options

import nimcypher/algos/common
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

# Scalar-reference AEAD (XChaCha20-Poly1305), using the always-available
# scalar ChaCha20 one-shots, so it can be timed side by side with the SIMD
# library build.
proc lockAuthScalar(key: array[32, byte], ad, cipherText: openArray[byte]):
    array[16, byte] =
  var sizes: array[16, byte]
  store64Le(cast[BytePtr](unsafeAddr sizes[0]), uint64(ad.len))
  store64Le(cast[BytePtr](unsafeAddr sizes[8]), uint64(cipherText.len))
  var polyCtx: Poly1305Context
  initPoly1305(polyCtx, key)
  update(polyCtx, ad)
  let adGap = gap(ad.len, 16)
  if adGap > 0:
    update(polyCtx, newSeq[byte](adGap))
  update(polyCtx, cipherText)
  let ctGap = gap(cipherText.len, 16)
  if ctGap > 0:
    update(polyCtx, newSeq[byte](ctGap))
  update(polyCtx, sizes)
  result = final(polyCtx)

proc aeadLockScalar(key: array[32, byte], nonce: array[24, byte],
                    plaintext: openArray[byte]):
    (seq[byte], array[16, byte]) =
  var nonce16: array[16, byte]
  for i in 0 ..< 16:
    nonce16[i] = nonce[i]
  let skey = chacha20HScalar(key, nonce16)
  var nonce8: array[8, byte]
  for i in 0 ..< 8:
    nonce8[i] = nonce[16 + i]
  var authKey: array[64, byte]
  discard chacha20DjbScalar(cast[BytePtr](unsafeAddr authKey[0]), nil, 64,
                            skey, nonce8, 0)
  result[0] = newSeqUninit[byte](plaintext.len)
  var dp = if plaintext.len > 0: cast[BytePtr](unsafeAddr plaintext[0]) else: nil
  var rp = if result[0].len > 0: cast[BytePtr](unsafeAddr result[0][0]) else: nil
  discard chacha20DjbScalar(rp, dp, plaintext.len, skey, nonce8, 1)
  var auth32: array[32, byte]
  for i in 0 ..< 32:
    auth32[i] = authKey[i]
  result[1] = lockAuthScalar(auth32, [], result[0])

proc aeadUnlockScalar(key: array[32, byte], nonce: array[24, byte],
                      ciphertext: openArray[byte],
                      mac: array[16, byte]): Option[seq[byte]] =
  var nonce16: array[16, byte]
  for i in 0 ..< 16:
    nonce16[i] = nonce[i]
  let skey = chacha20HScalar(key, nonce16)
  var nonce8: array[8, byte]
  for i in 0 ..< 8:
    nonce8[i] = nonce[16 + i]
  var authKey: array[64, byte]
  discard chacha20DjbScalar(cast[BytePtr](unsafeAddr authKey[0]), nil, 64,
                            skey, nonce8, 0)
  var auth32: array[32, byte]
  for i in 0 ..< 32:
    auth32[i] = authKey[i]
  let realMac = lockAuthScalar(auth32, [], ciphertext)
  if constantTimeEqual(mac, realMac):
    var plain = newSeqUninit[byte](ciphertext.len)
    var cp = if ciphertext.len > 0: cast[BytePtr](unsafeAddr ciphertext[0]) else: nil
    var rp = if plain.len > 0: cast[BytePtr](unsafeAddr plain[0]) else: nil
    discard chacha20DjbScalar(rp, cp, ciphertext.len, skey, nonce8, 1)
    result = some(plain)

proc bench(label: string, iterations: int, c, n: proc() {.closure.},
           ns: proc() {.closure.} = nil) =
  let ct = timeIt(iterations, c)
  let nt = timeIt(iterations, n)
  if ns.isNil:
    echo fmt"| {label} | {iterations} | {ct:.4f}s | {nt:.4f}s | - | {ct / nt:.2f}x | - |"
  else:
    let st = timeIt(iterations, ns)
    echo fmt"| {label} | {iterations} | {ct:.4f}s | {nt:.4f}s | {st:.4f}s | {ct / nt:.2f}x | {ct / st:.2f}x |"

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
    var ctS = newSeq[uint8](size)
    bench("chacha20 " & $size & "B", iters,
      proc() =
        discard crypto_chacha20_djb(addr ctC[0], toPtr(msg), csize_t(msg.len),
                                    addr key[0], addr nonce[0], 0)
        sink = sink xor ctC[0],
      proc() =
        discard chacha20DjbScalar(cast[BytePtr](unsafeAddr ctS[0]),
                                  cast[BytePtr](toPtr(msg)), size, key, nonce, 0)
        sink = sink xor ctS[0],
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
        let (c, t) = aeadLockScalar(key, nonce, msg)
        discard aeadUnlockScalar(key, nonce, c, t)
        sink = sink xor c[0],
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
  echo "NimCypher+SIMD uses the SIMD-accelerated kernels ('-' = no SIMD kernel for this primitive)"
  echo ""
  echo "| operation | iters | Monocypher | NimCypher | NimCypher+SIMD | M/Nim | M/SIMD |"
  echo "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
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
