# Interop tests: pure-Nim nimcypher port vs the real C Monocypher library.
#
# Uses the low-level FFI bindings in `monocypher_ffi.nim` (copied from the
# openpeeps/e2ee nimble package) to call the installed C Monocypher library,
# and cross-checks every primitive against the pure-Nim implementation.
#
# Requires the C Monocypher library (headers + libmonocypher.a) installed
# and discoverable via pkg-config.

import std/options
import std/unittest

import nimcypher/algos/common
import nimcypher/algos/blake2b
import nimcypher/algos/chacha20
import nimcypher/algos/poly1305
import nimcypher/algos/aead
import nimcypher/algos/argon2
import nimcypher/algos/x25519
import nimcypher/algos/eddsa
import nimcypher/algos/elligator
import nimcypher/algos/sha512
import nimcypher/algos/hkdf
import nimcypher/algos/ed25519

import monocypher_ffi

proc sameBytes(a, b: openArray[byte]): bool =
  if a.len != b.len:
    return false
  for i in 0 ..< a.len:
    if a[i] != b[i]:
      return false
  true

test "blake2b interop (smoke)":
  var msg: seq[byte]
  for i in 0 ..< 100:
    msg.add(byte(i * 3 + 1))
  var hashC: array[64, uint8]
  crypto_blake2b(addr hashC[0], 64, toPtr(msg), csize_t(msg.len))
  check sameBytes(hashC, blake2b(msg))

test "X25519 key exchange interop":
  # Alice uses C Monocypher, Bob uses the pure-Nim port
  var skA: array[32, uint8]
  for i in 0 ..< 32: skA[i] = byte(i * 5 + 1)
  var pkA: array[32, uint8]
  crypto_x25519_public_key(addr pkA[0], addr skA[0])
  # Nim public key must match the C public key
  let pkA_nim = x25519PublicKey(skA)
  check pkA == pkA_nim

  var skB: array[32, byte]
  for i in 0 ..< 32: skB[i] = byte(250 - i * 3)
  let pkB = x25519PublicKey(skB)

  # shared secrets computed on both sides must be identical
  var sharedC: array[32, uint8]
  crypto_x25519(addr sharedC[0], addr skA[0], toPtr(pkB))
  let sharedN = x25519(skA, pkB)
  check sameBytes(sharedC, sharedN)

  # mutual Diffie-Hellman: both directions agree
  let sharedBobN = x25519(skB, pkA)
  var sharedBobC: array[32, uint8]
  crypto_x25519(addr sharedBobC[0], addr skB[0], addr pkA[0])
  check sameBytes(sharedBobC, sharedBobN)
  check sameBytes(sharedC, sharedBobN)

test "X25519 conversions, dirty keys and inverse interop":
  var skA: array[32, uint8]
  for i in 0 ..< 32: skA[i] = byte(i * 5 + 1)
  var pkA: array[32, uint8]
  crypto_x25519_public_key(addr pkA[0], addr skA[0])
  var pkB: array[32, byte]
  for i in 0 ..< 32: pkB[i] = byte(100 - i)

  # x25519 <-> eddsa conversions
  var eddsaC: array[32, uint8]
  crypto_x25519_to_eddsa(addr eddsaC[0], addr pkA[0])
  check eddsaC == x25519ToEddsa(pkA)
  var x25519C: array[32, uint8]
  crypto_eddsa_to_x25519(addr x25519C[0], addr eddsaC[0])
  check x25519C == eddsaToX25519(eddsaC)

  # dirty ephemeral keys
  var dirtyC: array[32, uint8]
  crypto_x25519_dirty_fast(addr dirtyC[0], addr skA[0])
  check dirtyC == x25519DirtyFast(skA)
  var dirtySC: array[32, uint8]
  crypto_x25519_dirty_small(addr dirtySC[0], addr skA[0])
  check dirtySC == x25519DirtySmall(skA)

  # scalar inverse (OPRF)
  var blindC: array[32, uint8]
  crypto_x25519_inverse(addr blindC[0], addr skA[0], addr pkB[0])
  check blindC == x25519Inverse(skA, pkB)

test "EdDSA (BLAKE2b) sign/verify interop":
  var seed: array[32, uint8]
  for i in 0 ..< 32: seed[i] = byte(i * 7 + 2)
  var seedCopy = seed # crypto_eddsa_key_pair wipes the seed in place
  var skC: array[64, uint8]
  var pkC: array[32, uint8]
  crypto_eddsa_key_pair(addr skC[0], addr pkC[0], addr seed[0])
  let (skN, pkN) = eddsaKeyPair(seedCopy)
  check pkC == pkN

  var msg: seq[byte]
  for i in 0 ..< 50: msg.add(byte(i * 3 + 7))

  # C signs, Nim verifies
  var sigC: array[64, uint8]
  crypto_eddsa_sign(addr sigC[0], addr skC[0], toPtr(msg), csize_t(msg.len))
  check eddsaCheck(sigC, pkC, msg)

  # Nim signs, C verifies
  let sigN = eddsaSign(msg, skN)
  check crypto_eddsa_check(addr sigN[0], addr pkN[0], toPtr(msg),
                           csize_t(msg.len)) == 0

  # corrupted signatures are rejected by both
  var badC = sigC
  badC[10] = byte(int(badC[10]) + 1)
  check not eddsaCheck(badC, pkC, msg)
  check crypto_eddsa_check(addr badC[0], addr pkC[0], toPtr(msg),
                           csize_t(msg.len)) != 0
  var badN = sigN
  badN[3] = badN[3] xor 1
  check crypto_eddsa_check(addr badN[0], addr pkN[0], toPtr(msg),
                           csize_t(msg.len)) != 0

test "Ed25519 (SHA-512) sign/verify interop":
  var seed: array[32, uint8]
  for i in 0 ..< 32: seed[i] = byte(i * 7 + 2)
  var seedCopy = seed # crypto_ed25519_key_pair wipes the seed in place
  var skC: array[64, uint8]
  var pkC: array[32, uint8]
  crypto_ed25519_key_pair(addr skC[0], addr pkC[0], addr seed[0])
  let (skN, pkN) = ed25519KeyPair(seedCopy)
  check pkC == pkN

  var msg: seq[byte]
  for i in 0 ..< 50: msg.add(byte(i * 3 + 7))

  var sigC: array[64, uint8]
  crypto_ed25519_sign(addr sigC[0], addr skC[0], toPtr(msg), csize_t(msg.len))
  check ed25519Check(sigC, pkC, msg)

  let sigN = ed25519Sign(msg, skN)
  check crypto_ed25519_check(addr sigN[0], addr pkN[0], toPtr(msg),
                             csize_t(msg.len)) == 0

  var bad = sigC
  bad[0] = bad[0] xor 1
  check not ed25519Check(bad, pkC, msg)
  check crypto_ed25519_check(addr bad[0], addr pkC[0], toPtr(msg),
                             csize_t(msg.len)) != 0

test "AEAD encrypt/decrypt interop":
  var key: array[32, uint8]
  var nonce: array[24, uint8]
  for i in 0 ..< 32: key[i] = byte(i + 1)
  for i in 0 ..< 24: nonce[i] = byte(100 + i)
  var ad: seq[byte]
  for i in 0 ..< 5: ad.add(byte(i * 5))
  var pt: seq[byte]
  for i in 0 ..< 33: pt.add(byte(i * 11 + 3))

  # C encrypts, Nim decrypts
  var ctC: array[128, uint8]
  var macC: array[16, uint8]
  crypto_aead_lock(addr ctC[0], addr macC[0], addr key[0], addr nonce[0],
                   toPtr(ad), csize_t(ad.len), toPtr(pt), csize_t(pt.len))
  let decN = aeadUnlock(key, nonce, ctC.toOpenArray(0, pt.len - 1), macC, ad)
  check decN.isSome
  check sameBytes(decN.get, pt)

  # Nim encrypts, C decrypts
  let (ctN, macN) = aeadLock(key, nonce, pt, ad)
  var plainC: array[128, uint8]
  let rc = crypto_aead_unlock(addr plainC[0], addr macN[0], addr key[0],
                              addr nonce[0], toPtr(ad), csize_t(ad.len),
                              toPtr(ctN), csize_t(ctN.len))
  check rc == 0
  check sameBytes(plainC.toOpenArray(0, pt.len - 1), pt)

  # ciphertext and MAC are byte-identical across implementations
  let (ctN2, macN2) = aeadLock(key, nonce, pt, ad)
  check sameBytes(ctN2, ctC.toOpenArray(0, pt.len - 1))
  check macN2 == macC

  # tampered MAC is rejected by Nim
  var badMac = macC
  badMac[0] = badMac[0] xor 1
  check aeadUnlock(key, nonce, ctC.toOpenArray(0, pt.len - 1), badMac, ad).isNone

test "AEAD streaming interop":
  var key: array[32, uint8]
  var nonce: array[24, uint8]
  for i in 0 ..< 32: key[i] = byte(200 - i)
  for i in 0 ..< 24: nonce[i] = byte(i * 9)

  var ctxC: crypto_aead_ctx
  crypto_aead_init_x(addr ctxC, addr key[0], addr nonce[0])
  var writerN: AeadContext
  initX(writerN, key, nonce)
  var readerN: AeadContext
  initX(readerN, key, nonce)

  for chunk in 0 ..< 6:
    var pt: seq[byte]
    for j in 0 ..< 8: pt.add(byte(chunk * 8 + j))
    var ad: seq[byte]
    ad.add(byte(chunk))

    # C writes
    var ctC: array[64, uint8]
    var macC: array[16, uint8]
    crypto_aead_write(addr ctxC, addr ctC[0], addr macC[0],
                      toPtr(ad), csize_t(ad.len), toPtr(pt), csize_t(pt.len))
    # Nim writer produces identical output
    let (ctN, macN) = write(writerN, pt, ad)
    check sameBytes(ctN, ctC.toOpenArray(0, pt.len - 1))
    check macN == macC
    # Nim reader decrypts C's chunk (contexts stay in lockstep)
    let back = read(readerN, ctC.toOpenArray(0, pt.len - 1), macC, ad)
    check back.isSome
    check sameBytes(back.get, pt)

test "ChaCha20 stream interop":
  var key: array[32, uint8]
  for i in 0 ..< 32: key[i] = byte(i)
  var nonce8: array[8, uint8]
  var nonce12: array[12, uint8]
  var nonce24: array[24, uint8]
  for i in 0 ..< 8: nonce8[i] = byte(i * 3)
  for i in 0 ..< 12: nonce12[i] = byte(i * 3)
  for i in 0 ..< 24: nonce24[i] = byte(i * 3)

  var pt: seq[byte]
  for i in 0 ..< 100: pt.add(byte(i * 7 + 1))

  # DJB variant
  var ctC: array[160, uint8]
  discard crypto_chacha20_djb(addr ctC[0], toPtr(pt), csize_t(pt.len),
                              addr key[0], addr nonce8[0], 3'u64)
  check sameBytes(chacha20(pt, key, nonce8, 3), ctC.toOpenArray(0, pt.len - 1))

  # IETF variant
  var ctI: array[160, uint8]
  discard crypto_chacha20_ietf(addr ctI[0], toPtr(pt), csize_t(pt.len),
                               addr key[0], addr nonce12[0], 1'u32)
  check sameBytes(chacha20Ietf(pt, key, nonce12, 1),
                  ctI.toOpenArray(0, pt.len - 1))

  # XChaCha20
  var ctX: array[160, uint8]
  discard crypto_chacha20_x(addr ctX[0], toPtr(pt), csize_t(pt.len),
                            addr key[0], addr nonce24[0], 3'u64)
  check sameBytes(chacha20X(pt, key, nonce24, 3),
                  ctX.toOpenArray(0, pt.len - 1))

  # HChaCha20
  var nonce16: array[16, uint8]
  for i in 0 ..< 16: nonce16[i] = byte(i * 5)
  var hC: array[32, uint8]
  crypto_chacha20_h(addr hC[0], addr key[0], addr nonce16[0])
  check hC == chacha20H(key, nonce16)

test "Poly1305 interop":
  var key32: array[32, uint8]
  for i in 0 ..< 32: key32[i] = byte(255 - i)
  var msg: seq[byte]
  for i in 0 ..< 50: msg.add(byte(i * 13 + 5))

  # one-shot
  var macC: array[16, uint8]
  crypto_poly1305(macC, toPtr(msg), csize_t(msg.len), key32)
  let macN = poly1305(msg, key32)
  check macC == macN

  # incremental (both implementations)
  var ctxC: crypto_poly1305_ctx
  crypto_poly1305_init(addr ctxC, key32)
  crypto_poly1305_update(addr ctxC, toPtr(msg), csize_t(msg.len))
  var macC2: array[16, uint8]
  crypto_poly1305_final(addr ctxC, macC2)
  check macC2 == macC

  var ctxN: Poly1305Context
  initPoly1305(ctxN, key32)
  update(ctxN, msg)
  let macN2 = final(ctxN)
  check macN2 == macN
  check macN2 == macC

test "BLAKE2b / SHA-512 / HMAC / HKDF interop":
  var key: seq[byte]
  for i in 0 ..< 32: key.add(byte(i * 5 + 2))
  var msg: seq[byte]
  for i in 0 ..< 100: msg.add(byte(i * 7))

  # BLAKE2b
  var hC: array[64, uint8]
  crypto_blake2b(addr hC[0], 64, toPtr(msg), csize_t(msg.len))
  check sameBytes(hC, blake2b(msg))
  # custom hash size
  var h16: array[16, uint8]
  crypto_blake2b(addr h16[0], 16, toPtr(msg), csize_t(msg.len))
  check sameBytes(h16, blake2b(msg, 16))
  # keyed
  var hkC: array[64, uint8]
  crypto_blake2b_keyed(addr hkC[0], 64, toPtr(key), csize_t(key.len),
                       toPtr(msg), csize_t(msg.len))
  check sameBytes(hkC, keyedBlake2b(msg, key))

  # SHA-512
  var shC: array[64, uint8]
  crypto_sha512(addr shC[0], toPtr(msg), csize_t(msg.len))
  check sameBytes(shC, sha512(msg))

  # HMAC-SHA-512
  var macC: array[64, uint8]
  crypto_sha512_hmac(addr macC[0], toPtr(key), csize_t(key.len),
                     toPtr(msg), csize_t(msg.len))
  check sameBytes(macC, sha512Hmac(key, msg))

  # HKDF-SHA-512
  var salt: seq[byte]
  for i in 0 ..< 16: salt.add(byte(i * 3))
  var info: seq[byte]
  for i in 0 ..< 3: info.add(byte(i + 1))
  var okmC: array[96, uint8]
  crypto_sha512_hkdf(addr okmC[0], 96, toPtr(key), csize_t(key.len),
                     toPtr(salt), csize_t(salt.len),
                     toPtr(info), csize_t(info.len))
  check sameBytes(sha512Hkdf(key, salt, info, 96), okmC)
  # HKDF expand
  var okmC2: array[64, uint8]
  crypto_sha512_hkdf_expand(addr okmC2[0], 64, toPtr(okmC), 96,
                            toPtr(info), csize_t(info.len))
  check sameBytes(sha512HkdfExpand(okmC, info, 64), okmC2)

test "Argon2 interop":
  var pass = @[byte(0x70), byte(0x61), byte(0x73), byte(0x73)]
  var salt: seq[byte]
  for i in 0 ..< 16: salt.add(byte(i * 7 + 1))
  var keyA: seq[byte]
  for i in 0 ..< 32: keyA.add(byte(i + 1))
  var adA: seq[byte]
  for i in 0 ..< 8: adA.add(byte(i * 3))

  let configs = [
    (CRYPTO_ARGON2_I, 8'u32, 1'u32, 1'u32),
    (CRYPTO_ARGON2_D, 16'u32, 2'u32, 1'u32),
    (CRYPTO_ARGON2_ID, 8'u32, 1'u32, 2'u32),
  ]
  for (alg, nbBlocks, nbPasses, nbLanes) in configs:
    var config = crypto_argon2_config(algorithm: uint32(alg),
                                      nb_blocks: nbBlocks,
                                      nb_passes: nbPasses,
                                      nb_lanes: nbLanes)
    var inputs = crypto_argon2_inputs(pass: toPtr(pass), salt: toPtr(salt),
                                      pass_size: uint32(pass.len),
                                      salt_size: uint32(salt.len))
    var extras = crypto_argon2_extras(key: toPtr(keyA), ad: toPtr(adA),
                                      key_size: uint32(keyA.len),
                                      ad_size: uint32(adA.len))
    var work = newSeq[uint8](int(nbBlocks) * 1024)
    var hashC: array[32, uint8]
    crypto_argon2(addr hashC[0], 32, cast[pointer](addr work[0]),
                  config, inputs, extras)

    var cfgN = Argon2Config(algorithm: Argon2Algorithm(alg),
                            nbBlocks: nbBlocks, nbPasses: nbPasses,
                            nbLanes: nbLanes)
    let hashN = argon2(cfgN, 32, pass, salt, keyA, adA)
    check sameBytes(hashC, hashN)

test "Elligator interop":
  var hidden: array[32, uint8]
  for i in 0 ..< 32: hidden[i] = byte(i * 11 + 1)
  var curveC: array[32, uint8]
  crypto_elligator_map(curveC, hidden)
  let curveN = elligatorMap(hidden)
  check curveC == curveN

  for tweak in [0x00'u8, 0x42'u8, 0xc0'u8, 0xff'u8]:
    var repC: array[32, uint8]
    let rc = crypto_elligator_rev(repC, curveC, tweak)
    let repN = elligatorRev(curveN, tweak)
    check (rc == 0) == repN.isSome
    if rc == 0:
      check repC == repN.get

  # key pair generation
  var seed: array[32, uint8]
  for i in 0 ..< 32: seed[i] = byte(i * 3)
  var seedCopy = seed # crypto_elligator_key_pair wipes the seed in place
  var hiddenC: array[32, uint8]
  var skC: array[32, uint8]
  crypto_elligator_key_pair(hiddenC, skC, seed)
  let (hiddenN, skN) = elligatorKeyPair(seedCopy)
  check hiddenC == hiddenN
  check skC == skN

test "constant time verification interop":
  var a16: array[16, uint8]
  var b16: array[16, uint8]
  for i in 0 ..< 16:
    a16[i] = byte(i)
    b16[i] = byte(i)
  check crypto_verify16(addr a16[0], addr b16[0]) == 0
  check constantTimeEqual(a16, b16)
  b16[7] = 0
  check crypto_verify16(addr a16[0], addr b16[0]) != 0
  check not constantTimeEqual(a16, b16)

  var a32: array[32, uint8]
  var b32: array[32, uint8]
  for i in 0 ..< 32:
    a32[i] = byte(i * 3)
    b32[i] = byte(i * 3)
  check crypto_verify32(addr a32[0], addr b32[0]) == 0
  check constantTimeEqual(a32, b32)
  b32[31] = 1
  check crypto_verify32(addr a32[0], addr b32[0]) != 0
  check not constantTimeEqual(a32, b32)
