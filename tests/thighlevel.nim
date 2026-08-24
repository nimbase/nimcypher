import std/unittest

import nimcypher

import nimcypher/algos/aead as aeadAlgo
import nimcypher/algos/eddsa as eddsaAlgo
import nimcypher/algos/x25519 as xAlgo

test "utils: hex, arrays, strings, random":
  let data = @[byte 0xde, 0xad, 0xbe, 0xef]
  check toHex(data) == "DEADBEEF"
  check fromHex[4, uint8]("DEADBEEF") == data
  check fromHex[4, uint8]("deadbeef") == data # case-insensitive
  check toBytes("abc") == @[byte('a'), byte('b'), byte('c')]
  check toString(@[byte('a'), byte('b'), byte('c')]) == "abc"
  let k = toArray[32](newSeq[byte](32))
  check k.len == 32
  expect ValueError:
    discard toArray[32](newSeq[byte](31))
  let rnd = randomBytes[32]()
  check rnd.len == 32
  check constantTimeEqual(@[byte 1, 2], @[byte 1, 2])
  check not constantTimeEqual(@[byte 1, 2], @[byte 1, 3])
  var secret = @[byte 9, 9, 9]
  wipe(secret)
  check secret == @[byte 0, 0, 0]

test "hash: blake known digests and hex":
  let msg = toBytes("hello world")
  # known BLAKE2b digests of "hello world"
  check toHex(blake(msg, 32)) == "256C83B297114D201B30179F3F0EF0CACE9783622DA5974326B436178AEEF610"
  check toHex(blake(msg, 64)) == "021CED8799296CECA557832AB941A50B4A11F83478CF141F51F933F653AB9FBC" &
                                 "C05A037CDDBED06E309BF334942C4E58CDF1A46E237911CCD7FCF9787CBC7FD0"
  check blakeHex(msg, 32).len == 64
  check blake("hello world") == blake(msg)
  # keyed
  check toHex(blakeKeyed(msg, toBytes("key"))) == "70E4D5080EA1C43926E3BAB251812DEC5FA0D53687E9F7D59C6BE6474913928A"
  check blakeKeyedHex(msg, toBytes("key")).len == 64

test "hash: streaming blake2b":
  var h = initBlake2b(64)
  update(h, toBytes("hello "))
  update(h, toBytes("world"))
  check finish(h) == blake("hello world", 64)
  var hk = initBlake2bKeyed(toBytes("key"))
  update(hk, toBytes("msg"))
  check finishHex(hk) == blakeKeyedHex(toBytes("msg"), toBytes("key"))

test "hash: sha512, hmac, hkdf":
  check sha512Hex(toBytes("abc")).len == 128
  check sha512("abc") == sha512(toBytes("abc"))
  # streaming sha512
  var s = initSha512()
  update(s, toBytes("a"))
  update(s, toBytes("bc"))
  check finish(s) == sha512("abc")
  # hmac
  let hmac = sha512Hmac(toBytes("key"), toBytes("msg"))
  check hmac.len == 64
  check sha512Hmac("key", "msg") == hmac
  # hkdf
  let okm = hkdfSha512(toBytes("ikm"), @[], toBytes("info"), 32)
  check okm.len == 32
  check hkdfSha512("ikm", "", "info", 32) == okm
  let okm32 = hkdfSha512[32](toBytes("ikm"), @[], toBytes("info"))
  check okm32 == okm
  # verifyDigest
  check verifyDigest(@[byte 1, 2], @[byte 1, 2])
  check not verifyDigest(@[byte 1, 2], @[byte 1, 3])

test "encrypt: AEAD round trip and failure":
  let key = randomBytes[32]()
  let nonce = randomBytes[24]()
  let plain = toBytes("Attack at dawn")
  let (ct, mac) = encrypt(plain, key, nonce)
  check decrypt(ct, mac, key, nonce) == plain
  # string convenience
  let (ct2, mac2) = encrypt("Attack at dawn", key, nonce)
  check decrypt(toString(ct2), mac2, key, nonce) == "Attack at dawn"
  # tampered mac fails
  var bad = mac
  bad[0] = bad[0] xor 1
  expect(ValueError):
    discard decrypt(ct, bad, key, nonce)
  # matches low-level
  let (ctL, macL) = aeadAlgo.aeadLock(key, nonce, plain)
  check ct == ctL and mac == macL

test "encrypt: seal/unseal":
  let key = randomBytes[32]()
  let msg = seal(toBytes("secret message"), key)
  check unseal(msg, key) == toBytes("secret message")
  # tampering is detected
  var tampered = msg
  tampered.cipherText[0] = tampered.cipherText[0] xor 1
  expect(ValueError):
    discard unseal(tampered, key)

test "encrypt: streaming AEAD":
  let key = randomBytes[32]()
  let nonce = randomBytes[24]()
  var writer = aeadStreamInitX(key, nonce)
  var reader = aeadStreamInitX(key, nonce)
  for chunk in 0 ..< 4:
    var pt: seq[byte]
    for j in 0 ..< 8: pt.add(byte(chunk * 8 + j))
    let (ct, mac) = aeadStreamWrite(writer, pt)
    check aeadStreamRead(reader, ct, mac) == pt

test "encrypt: key exchange":
  let alice = x25519KeyPair(randomBytes[32]())
  let bob = x25519KeyPair(randomBytes[32]())
  let aliceShared = sharedSecret(alice[0], bob[1])
  let bobShared = sharedSecret(bob[0], alice[1])
  check aliceShared == bobShared
  # no-arg key pair uses a random secret; public key matches low-level
  let (sk, pk) = x25519KeyPair()
  check pk == xAlgo.x25519PublicKey(sk)

test "encrypt: challenge-response MAC":
  let secret = randomBytes[32]()
  let challenge = randomBytes[16]()
  let mac = computeChallengeMac(secret, challenge)
  check verifyChallengeMac(secret, challenge, mac)
  var bad = mac
  bad[0] = bad[0] xor 1
  check not verifyChallengeMac(secret, challenge, bad)

test "sign: key pairs, sign and verify":
  let seed = randomBytes[32]()
  let kp = generateSigningKeyPair(seed)
  let msg = toBytes("hello")
  let sig = sign(kp.secretKey, msg)
  check verify(kp.publicKey, msg, sig)
  # tampered signature rejected
  var bad = sig
  bad[0] = bad[0] xor 1
  check not verify(kp.publicKey, msg, bad)
  # wrong message rejected
  check not verify(kp.publicKey, toBytes("hello!"), sig)
  # random key pair produces a different signature
  let kp2 = generateSigningKeyPair()
  check sign(kp2.secretKey, msg) != sign(kp.secretKey, msg)
  # matches low-level
  let (sk, pk) = eddsaAlgo.eddsaKeyPair(seed)
  check kp.publicKey == pk and kp.secretKey.data == sk

test "sign: hex helpers":
  let kp = generateSigningKeyPair(randomBytes[32]())
  let sig = sign(kp.secretKey, toBytes("m"))
  check publicKeyFromHex(publicKeyToHex(kp.publicKey)) == kp.publicKey
  check secretKeyFromHex(secretKeyToHex(kp.secretKey)) == kp.secretKey.data
  check signatureFromHex(signatureToHex(sig)) == sig
  expect(ValueError):
    discard publicKeyFromHex("zz")

test "password: hash, verify, derive":
  let stored = hashPassword("hunter2")
  check verifyPassword("hunter2", stored)
  check not verifyPassword("hunter3", stored)
  # malformed stored hash
  check not verifyPassword("hunter2", "not-a-hash")
  # derive key deterministically
  let salt = generateSalt()
  let k1 = deriveKeyFromPassword("pw", salt)
  let k2 = deriveKeyFromPassword("pw", salt)
  check k1 == k2
  check k1 != deriveKeyFromPassword("pw2", salt)
  # key pair from password
  let (sk, pk) = keyPairFromPassword("pw", salt)
  check pk == xAlgo.x25519PublicKey(sk.data)

test "utils: generateSalt sizes and aead stream nonce validation":
  check generateSalt().len == 16
  check generateSalt(32).len == 32
  check generateSalt(8).len == 8
  let key = randomBytes[32]()
  expect ValueError:
    discard aeadStreamInit(aeadX, key, newSeq[byte](23))
  expect ValueError:
    discard aeadStreamInit(aeadDjb, key, newSeq[byte](9))
  expect ValueError:
    discard aeadStreamInit(aeadIetf, key, newSeq[byte](13))

test "secret: RAII wiping on scope exit":
  var data: array[16, byte]
  for i in 0 ..< 16: data[i] = byte(i + 1)
  var sink: ptr array[16, byte]
  block:
    var s = secret(data)
    sink = addr s.data
    check sink[][0] == 1
  # the wrapped array is wiped when the Secret goes out of scope
  check sink[] == default(array[16, byte])

test "aes: all six modes round-trip":
  let k16 = randomBytes[16]()
  let k24 = randomBytes[24]()
  let key = randomBytes[32]()
  let iv = randomBytes[16]()
  let data = toBytes("the quick brown fox jumps over the lazy dog")

  check aesEcbDecrypt(k16, aesEcbEncrypt(k16, data)) == data
  check aesCbcDecrypt(k24, iv, aesCbcEncrypt(k24, iv, data)) == data
  check aesCtrCrypt(key, iv, aesCtrCrypt(key, iv, data)) == data
  check aesOfbCrypt(key, iv, aesOfbCrypt(key, iv, data)) == data
  check aesCfbEncrypt(key, iv, data) != data # sanity: actually encrypts
  check aesCfbDecrypt(key, iv, aesCfbEncrypt(key, iv, data)) == data

  # raw (unpadded) ECB/CBC need aligned input
  let aligned = newSeq[byte](32)
  check aesEcbDecrypt(k16, aesEcbEncrypt(k16, aligned, false), false).len == 32

test "aes-gcm: seal/open and tamper rejection":
  let key = randomBytes[32]()
  let msg = toBytes("attack at dawn")
  let sealed = gcmSeal(msg, key)
  check gcmOpen(sealed, key) == msg
  check sealed.nonce.len == 12
  var bad = sealed
  bad.cipherText[0] = bad.cipherText[0] xor byte(1)
  expect ValueError:
    discard gcmOpen(bad, key)

test "aes-gcm: one-shot with AAD and explicit nonce":
  let key = randomBytes[16]()
  let nonce = randomBytes[12]()
  let (ct, tag) = aesGcmEncrypt(key, nonce, toBytes("payload"),
                                toBytes("header"))
  check aesGcmDecryptStr(key, nonce, ct, tag, toBytes("header")) == "payload"
  expect ValueError:
    discard aesGcmDecrypt(key, nonce, ct, tag, toBytes("wrong"))

test "aes-gcm: streaming equals one-shot":
  let key = randomBytes[32]()
  let nonce = randomBytes[12]()
  let data = toBytes("streaming authenticated encryption of a longer message")
  var st = gcmStreamInit(key, nonce, [], true)
  var ct = gcmStreamUpdate(st, data[0 ..< 9])
  ct.add(gcmStreamUpdate(st, data[9 ..^ 1]))
  let tag = gcmStreamFinal(st)
  var ds = gcmStreamInit(key, nonce, [], false)
  var pt = gcmStreamUpdate(ds, ct)
  check gcmStreamVerify(ds, @tag)
  check pt == data
