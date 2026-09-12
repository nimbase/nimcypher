# RSA: RSASSA-PKCS1-v1_5, RSASSA-PSS, RSAES-OAEP, key generation.
#
# Pure Nim on `pkg/bigints` plus an internal Montgomery sliding-window
# exponentiation (`internal/montgomery.fastPowmod`, ~30x faster than the
# generic `powmod` on RSA-2048). Private operations use CRT + RSA blinding
# to mitigate the variable-time arithmetic. Randomness from `std/sysrand`.
# Hashes from nimcypher (`sha1/sha256/sha384/sha512`).
#
# JOSE mapping (RFC 7518): RS256/384/512 = PKCS1-v1_5 with SHA-256/384/512;
# PS256/384/512 = PSS with MGF1-SHA and salt len = hash len;
# RSA-OAEP = OAEP-SHA1, RSA-OAEP-256 = OAEP-SHA256; RSA1_5 = PKCS1-v1_5
# encryption (legacy).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import bigints

import ./common
import ./bigint_ext
import ./internal/montgomery
import ./internal/montgomery64
import ./sha1 as sha1Algo
import ./sha256 as sha256Algo
import ./sha384 as sha384Algo
import ./sha512 as sha512Algo

{.push checks: off.}

type
  RsaHash* = enum
    ## Hash paired with an RSA padding. `rhSha1` is only valid for OAEP
    ## (`RSA-OAEP`); signatures use SHA-2.
    rhSha1, rhSha256, rhSha384, rhSha512

  RsaPublicKey* = object
    n*: BigInt
    e*: BigInt
    k*: int ## modulus byte length (I2OSP width)

  RsaPrivateKey* = object
    n*: BigInt
    e*: BigInt
    d*: BigInt
    p*: BigInt
    q*: BigInt
    dp*: BigInt
    dq*: BigInt
    qinv*: BigInt
    k*: int

proc wipe*(key: var RsaPrivateKey) =
  ## Best-effort wipe of private material. `pkg/bigints` keeps limbs in a
  ## managed `seq`, so this drops all references (GC frees the backing
  ## buffers); it does not scrub freed memory. Ephemeral buffers
  ## (`seq[byte]`) elsewhere in this module ARE scrubbed via `wipe`.
  key.d = initBigInt(0)
  key.p = initBigInt(0)
  key.q = initBigInt(0)
  key.dp = initBigInt(0)
  key.dq = initBigInt(0)
  key.qinv = initBigInt(0)
  key.n = initBigInt(0)
  key.e = initBigInt(0)
  key.k = 0

## NOTE: no `=destroy` hook is installed on purpose: the BigInt-backed
## fields live in managed seqs, so an implicit destructor already exists;
## call `wipe` explicitly when done with a private key.

# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

func hashLen*(h: RsaHash): int =
  case h
  of rhSha1: 20
  of rhSha256: 32
  of rhSha384: 48
  of rhSha512: 64

proc hashBytes(h: RsaHash, msg: openArray[byte]): seq[byte] =
  case h
  of rhSha1:
    let d = sha1Algo.sha1(msg)
    result = newSeq[byte](20)
    for i in 0 ..< 20: result[i] = d[i]
  of rhSha256:
    let d = sha256Algo.sha256(msg)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = d[i]
  of rhSha384:
    let d = sha384Algo.sha384(msg)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = d[i]
  of rhSha512:
    let d = sha512Algo.sha512(msg)
    result = newSeq[byte](64)
    for i in 0 ..< 64: result[i] = d[i]

proc mgf1(h: RsaHash, seed: openArray[byte], outLen: int): seq[byte] =
  ## MGF1 with the given hash (RFC 3447 App. B).
  if outLen < 0:
    raise newException(ValueError, "negative mask length")
  result = newSeq[byte](outLen)
  let hlen = hashLen(h)
  var counter: uint32 = 0
  var off = 0
  while off < outLen:
    var c: array[4, byte]
    c[0] = byte(counter shr 24); c[1] = byte(counter shr 16)
    c[2] = byte(counter shr 8); c[3] = byte(counter)
    var input = newSeq[byte](seed.len + 4)
    for i in 0 ..< seed.len: input[i] = seed[i]
    for i in 0 ..< 4: input[seed.len + i] = c[i]
    let digest = hashBytes(h, input)
    wipe(input)
    let take = min(hlen, outLen - off)
    for i in 0 ..< take: result[off + i] = digest[i]
    inc off, take
    inc counter

proc xorBytes(a: var openArray[byte], b: openArray[byte]) =
  assert a.len == b.len
  for i in 0 ..< a.len: a[i] = a[i] xor b[i]

# ---------------------------------------------------------------------------
# Raw modular exponentiation (public op + blinded CRT private op)
# ---------------------------------------------------------------------------

proc publicOp(key: RsaPublicKey, x: BigInt): BigInt =
  if x < initBigInt(0) or x >= key.n:
    raise newException(ValueError, "representative out of range")
  fastPowmod(x, key.e, key.n)

proc privateOpBlinded(key: RsaPrivateKey, x: BigInt): BigInt =
  ## CRT private op with RSA blinding (side-channel mitigation).
  if x < initBigInt(0) or x >= key.n:
    raise newException(ValueError, "representative out of range")
  let one = initBigInt(1)
  # blinding factor r in [1, n-1], gcd(r, n) == 1
  var r: BigInt
  for _ in 0 ..< 32:
    r = randomBigIntBelow(key.n)
    if gcd(r, key.n) == one:
      break
  if gcd(r, key.n) != one:
    raise newException(ValueError, "could not find blinding factor")
  let rInv = fastInvmod(r, key.n)
  let rPowE = fastPowmod(r, key.e, key.n)
  let blinded = (x * rPowE) mod key.n
  # CRT: m1 = b^dP mod p, m2 = b^dQ mod q (Montgomery, pure Nim)
  let m1 = fastPowmod(blinded mod key.p, key.dp, key.p)
  let m2 = fastPowmod(blinded mod key.q, key.dq, key.q)
  var diff = (m1 - m2) mod key.p
  if diff < initBigInt(0): diff += key.p
  let h = (key.qinv * diff) mod key.p
  let mBlind = m2 + key.q * h
  result = (mBlind * rInv) mod key.n

# ---------------------------------------------------------------------------
# Key construction / generation
# ---------------------------------------------------------------------------

proc rsaPublicKey*(n, e: BigInt): RsaPublicKey =
  if n <= initBigInt(0) or e <= initBigInt(0):
    raise newException(ValueError, "invalid RSA public key")
  let k = byteLen(n)
  if k < 12:
    raise newException(ValueError, "modulus too small")
  result = RsaPublicKey(n: n, e: e, k: k)

proc rsaPrivateKey*(n, e, d, p, q: BigInt): RsaPrivateKey =
  if p <= initBigInt(1) or q <= initBigInt(1):
    raise newException(ValueError, "invalid RSA primes")
  if p == q:
    raise newException(ValueError, "p and q must differ")
  if n != p * q:
    raise newException(ValueError, "n must equal p*q")
  let one = initBigInt(1)
  let dp = d mod (p - one)
  let dq = d mod (q - one)
  let qinv = invmod(q, p)
  result = RsaPrivateKey(n: n, e: e, d: d, p: p, q: q,
                         dp: dp, dq: dq, qinv: qinv, k: byteLen(n))

proc publicKey*(key: RsaPrivateKey): RsaPublicKey =
  RsaPublicKey(n: key.n, e: key.e, k: key.k)

proc generateRsaKeyPair*(bits = 2048, e = 65537): RsaPrivateKey =
  ## Generate an RSA key pair. `bits` is the modulus size (default 2048).
  ## `e` defaults to 65537. Sizes below 2048 are insecure and exist for
  ## tests only; JOSE callers must enforce >= 2048.
  if bits < 512 or (bits mod 8) != 0:
    raise newException(ValueError, "bits must be a multiple of 8 >= 512")
  if e <= 1 or (e mod 2) == 0:
    raise newException(ValueError, "e must be an odd integer > 1")
  let eBig = initBigInt(e)
  let one = initBigInt(1)
  let half = bits div 2
  while true:
    let p = randomPrime(half)
    var q = randomPrime(half)
    if p == q:
      continue
    # ensure exact modulus bit length and odd/even split
    let n = p * q
    if bitLen(n) != bits:
      continue
    let phi = (p - one) * (q - one)
    if gcd(eBig, phi) != one:
      continue
    let d = invmod(eBig, phi)
    # FIPS-style sanity: d must be large enough
    if bitLen(d) * 2 < bits:
      continue
    return rsaPrivateKey(n, eBig, d, p, q)

# ---------------------------------------------------------------------------
# RSASSA-PKCS1-v1_5 (RFC 3447 §8.2)
# ---------------------------------------------------------------------------

const
  prefixSha256: array[19, byte] = [0x30'u8, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0x04, 0x20]
  prefixSha384: array[19, byte] = [0x30'u8, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    0x04, 0x30]
  prefixSha512: array[19, byte] = [0x30'u8, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
    0x04, 0x40]

proc digestPrefix(h: RsaHash): seq[byte] =
  case h
  of rhSha256:
    result = newSeq[byte](prefixSha256.len)
    for i in 0 ..< prefixSha256.len: result[i] = prefixSha256[i]
  of rhSha384:
    result = newSeq[byte](prefixSha384.len)
    for i in 0 ..< prefixSha384.len: result[i] = prefixSha384[i]
  of rhSha512:
    result = newSeq[byte](prefixSha512.len)
    for i in 0 ..< prefixSha512.len: result[i] = prefixSha512[i]
  of rhSha1:
    raise newException(ValueError, "SHA-1 not allowed for PKCS#1 v1.5 signatures")

proc emsaPkcs1v15Encode(h: RsaHash, msg: openArray[byte], emLen: int): seq[byte] =
  let prefix = digestPrefix(h)
  let digest = hashBytes(h, msg)
  let tLen = prefix.len + digest.len
  if emLen < tLen + 11:
    raise newException(ValueError, "intended encoded message length too short")
  result = newSeq[byte](emLen)
  result[0] = 0x00; result[1] = 0x01
  let psLen = emLen - tLen - 3
  for i in 0 ..< psLen: result[2 + i] = 0xFF
  result[2 + psLen] = 0x00
  for i in 0 ..< prefix.len: result[3 + psLen + i] = prefix[i]
  for i in 0 ..< digest.len: result[3 + psLen + prefix.len + i] = digest[i]

proc pkcs1v15Sign*(key: RsaPrivateKey, h: RsaHash,
                   msg: openArray[byte]): seq[byte] =
  ## RSASSA-PKCS1-v1_5 sign (JWA RS256/384/512).
  var em = emsaPkcs1v15Encode(h, msg, key.k)
  let m = fromBytesBE(em)
  wipe(em)
  result = toBytesBE(privateOpBlinded(key, m), key.k)

proc pkcs1v15Verify*(key: RsaPublicKey, h: RsaHash,
                     msg: openArray[byte], sig: openArray[byte]): bool =
  ## RSASSA-PKCS1-v1_5 verify. Returns false (no exception) on bad signature.
  if sig.len != key.k:
    return false
  let expected = emsaPkcs1v15Encode(h, msg, key.k)
  let s = fromBytesBE(sig)
  if s >= key.n:
    return false
  let m = publicOp(key, s)
  let em = toBytesBE(m, key.k)
  result = constantTimeEqual(em, expected)

# ---------------------------------------------------------------------------
# RSASSA-PSS (RFC 3447 §8.1, JWA: saltLen = hashLen, MGF1 same hash)
# ---------------------------------------------------------------------------

proc emsaPssEncode(h: RsaHash, msg: openArray[byte], emBits: int,
                   salt: openArray[byte]): seq[byte] =
  let hlen = hashLen(h)
  let emLen = (emBits + 7) div 8
  if emLen < hlen + hlen + 2:
    raise newException(ValueError, "encoding error: key too short for PSS")
  let mHash = hashBytes(h, msg)
  var mPrime = newSeq[byte](8 + hlen + salt.len)
  # first 8 bytes are zero by construction
  for i in 0 ..< hlen: mPrime[8 + i] = mHash[i]
  for i in 0 ..< salt.len: mPrime[8 + hlen + i] = salt[i]
  let hDigest = hashBytes(h, mPrime)
  wipe(mPrime)
  var psLen = emLen - hlen - salt.len - 2
  var db = newSeq[byte](emLen - hlen - 1)
  for i in 0 ..< psLen: db[i] = 0x00
  db[psLen] = 0x01
  for i in 0 ..< salt.len: db[psLen + 1 + i] = salt[i]
  let dbMask = mgf1(h, hDigest, db.len)
  xorBytes(db, dbMask)
  # clear leftmost 8*emLen - emBits bits
  let excess = 8 * emLen - emBits
  if excess > 0:
    db[0] = db[0] and byte(0xFF shr excess)
  result = newSeq[byte](emLen)
  for i in 0 ..< db.len: result[i] = db[i]
  for i in 0 ..< hlen: result[db.len + i] = hDigest[i]
  result[^1] = 0xBC
  wipe(db)

proc pssSign*(key: RsaPrivateKey, h: RsaHash,
              msg: openArray[byte]): seq[byte] =
  ## RSASSA-PSS sign with saltLen = hashLen (JWA PS256/384/512).
  let hlen = hashLen(h)
  if h notin {rhSha256, rhSha384, rhSha512}:
    raise newException(ValueError, "PSS requires SHA-256/384/512")
  let salt = randomBytesSeq(hlen)
  var em = emsaPssEncode(h, msg, 8 * key.k - 1, salt)
  let m = fromBytesBE(em)
  wipe(em)
  result = toBytesBE(privateOpBlinded(key, m), key.k)

proc pssVerify*(key: RsaPublicKey, h: RsaHash, msg: openArray[byte],
                sig: openArray[byte]): bool =
  ## RSASSA-PSS verify (saltLen recovered, must equal hashLen per JWA).
  let hlen = hashLen(h)
  if h notin {rhSha256, rhSha384, rhSha512}:
    return false
  if sig.len != key.k:
    return false
  let emBits = 8 * key.k - 1
  let emLen = (emBits + 7) div 8
  let s = fromBytesBE(sig)
  if s >= key.n:
    return false
  let em = toBytesBE(publicOp(key, s), key.k)
  if em[^1] != 0xBC:
    return false
  let dbLen = emLen - hlen - 1
  var maskedDb = newSeq[byte](dbLen)
  var hDigest = newSeq[byte](hlen)
  for i in 0 ..< dbLen: maskedDb[i] = em[i]
  for i in 0 ..< hlen: hDigest[i] = em[dbLen + i]
  # RFC 8017 §9.1.2 step 4: the leftmost 8*emLen - emBits bits of the
  # leftmost octet of maskedDB (i.e. of EM itself, as transmitted) must
  # be zero -- the encoder cleared them.
  let excess = 8 * emLen - emBits
  if excess > 0:
    if (em[0] and byte((0xFF shl (8 - excess)) and 0xFF)) != 0:
      return false
  let dbMask = mgf1(h, hDigest, dbLen)
  xorBytes(maskedDb, dbMask)
  # RFC 8017 §9.1.2 step 6: clear those bits on DB before the PS check
  # (the unmasked top bits equal the mask's, i.e. random).
  if excess > 0:
    maskedDb[0] = maskedDb[0] and byte(0xFF shr excess)
  # DB = PS || 0x01 || salt, salt length must be hlen
  if dbLen < hlen + 1:
    return false
  let psLen = dbLen - hlen - 1
  for i in 0 ..< psLen:
    if maskedDb[i] != 0x00:
      return false
  if maskedDb[psLen] != 0x01:
    return false
  var salt = newSeq[byte](hlen)
  for i in 0 ..< hlen: salt[i] = maskedDb[psLen + 1 + i]
  var expect = emsaPssEncode(h, msg, emBits, salt)
  # compare H parts in constant time
  var ok = constantTimeEqual(expect, em)
  wipe(salt); wipe(maskedDb); wipe(hDigest); wipe(expect)
  result = ok

# ---------------------------------------------------------------------------
# RSAES-OAEP (RFC 3447 §7.1)
# ---------------------------------------------------------------------------

proc oaepEncode(h: RsaHash, msg: openArray[byte], k: int,
                label: openArray[byte] = []): seq[byte] =
  let hlen = hashLen(h)
  if msg.len > k - 2 * hlen - 2:
    raise newException(ValueError, "message too long for OAEP")
  let lHash = hashBytes(h, label)
  let psLen = k - msg.len - 2 * hlen - 2
  var db = newSeq[byte](k - hlen - 1)
  for i in 0 ..< hlen: db[i] = lHash[i]
  # PS is zeros by construction
  db[hlen + psLen] = 0x01
  for i in 0 ..< msg.len: db[hlen + psLen + 1 + i] = msg[i]
  let seed = randomBytesSeq(hlen)
  let dbMask = mgf1(h, seed, db.len)
  xorBytes(db, dbMask)
  let seedMask = mgf1(h, db, hlen)
  var maskedSeed = seed
  xorBytes(maskedSeed, seedMask)
  result = newSeq[byte](k)
  result[0] = 0x00
  for i in 0 ..< hlen: result[1 + i] = maskedSeed[i]
  for i in 0 ..< db.len: result[1 + hlen + i] = db[i]
  wipe(db); wipe(maskedSeed)

proc oaepDecode(h: RsaHash, em: openArray[byte],
                label: openArray[byte] = []): seq[byte] =
  let hlen = hashLen(h)
  let k = em.len
  if k < 2 * hlen + 2:
    raise newException(ValueError, "decryption error")
  if em[0] != 0x00:
    raise newException(ValueError, "decryption error")
  var maskedSeed = newSeq[byte](hlen)
  var maskedDb = newSeq[byte](k - hlen - 1)
  for i in 0 ..< hlen: maskedSeed[i] = em[1 + i]
  for i in 0 ..< maskedDb.len: maskedDb[i] = em[1 + hlen + i]
  let seedMask = mgf1(h, maskedDb, hlen)
  xorBytes(maskedSeed, seedMask)
  let dbMask = mgf1(h, maskedSeed, maskedDb.len)
  xorBytes(maskedDb, dbMask)
  let lHash = hashBytes(h, label)
  var lHashOk = true
  for i in 0 ..< hlen:
    if maskedDb[i] != lHash[i]: lHashOk = false
  if not lHashOk:
    wipe(maskedSeed); wipe(maskedDb)
    raise newException(ValueError, "decryption error")
  # find 0x01 after zero padding
  var oneIdx = -1
  for i in hlen ..< maskedDb.len:
    if maskedDb[i] == 0x01 and oneIdx < 0:
      oneIdx = i
      break
    if maskedDb[i] != 0x00 and oneIdx < 0 and maskedDb[i] != 0x01:
      wipe(maskedSeed); wipe(maskedDb)
      raise newException(ValueError, "decryption error")
  if oneIdx < 0:
    wipe(maskedSeed); wipe(maskedDb)
    raise newException(ValueError, "decryption error")
  # verify all bytes before oneIdx (after lHash) are zero
  for i in hlen ..< oneIdx:
    if maskedDb[i] != 0x00:
      wipe(maskedSeed); wipe(maskedDb)
      raise newException(ValueError, "decryption error")
  result = newSeq[byte](maskedDb.len - oneIdx - 1)
  for i in 0 ..< result.len: result[i] = maskedDb[oneIdx + 1 + i]
  wipe(maskedSeed); wipe(maskedDb)

proc oaepEncrypt*(key: RsaPublicKey, h: RsaHash, msg: openArray[byte],
                  label: openArray[byte] = []): seq[byte] =
  ## RSAES-OAEP encrypt. `rhSha1` = JWA `RSA-OAEP`, `rhSha256` = `RSA-OAEP-256`.
  if h notin {rhSha1, rhSha256}:
    raise newException(ValueError, "OAEP allows SHA-1 or SHA-256 only")
  var em = oaepEncode(h, msg, key.k, label)
  let m = fromBytesBE(em)
  wipe(em)
  result = toBytesBE(publicOp(key, m), key.k)

proc oaepDecrypt*(key: RsaPrivateKey, h: RsaHash, cipher: openArray[byte],
                  label: openArray[byte] = []): seq[byte] =
  ## RSAES-OAEP decrypt. Raises ValueError("decryption error") on failure.
  if h notin {rhSha1, rhSha256}:
    raise newException(ValueError, "OAEP allows SHA-1 or SHA-256 only")
  if cipher.len != key.k:
    raise newException(ValueError, "decryption error")
  let c = fromBytesBE(cipher)
  if c >= key.n:
    raise newException(ValueError, "decryption error")
  var em = toBytesBE(privateOpBlinded(key, c), key.k)
  result = oaepDecode(h, em, label)
  wipe(em)

# ---------------------------------------------------------------------------
# RSAES-PKCS1-v1_5 (JWA `RSA1_5`; legacy, new uses should prefer OAEP)
# ---------------------------------------------------------------------------

proc pkcs1v15Encode(msg: openArray[byte], k: int): seq[byte] =
  ## EME-PKCS1-v1_5-ENCODE (RFC 3447 7.2.1).
  if msg.len > k - 11:
    raise newException(ValueError, "message too long")
  result = newSeq[byte](k)
  result[0] = 0x00
  result[1] = 0x02
  let psLen = k - msg.len - 3
  var i = 0
  while i < psLen:
    let b = randomBytesSeq(psLen - i)
    for v in b:
      if i >= psLen: break
      if v != 0x00:
        result[2 + i] = v
        inc i
  result[2 + psLen] = 0x00
  for j in 0 ..< msg.len: result[3 + psLen + j] = msg[j]

proc pkcs1v15Decode(em: openArray[byte]): seq[byte] =
  ## EME-PKCS1-v1_5-DECODE with strict checks. Single "decryption error"
  ## message on all failures (Bleichenbacher mitigation: no oracle detail).
  let k = em.len
  if k < 11:
    raise newException(ValueError, "decryption error")
  if em[0] != 0x00 or em[1] != 0x02:
    raise newException(ValueError, "decryption error")
  var sep = -1
  for i in 2 ..< k:
    if em[i] == 0x00:
      sep = i
      break
    # PS bytes must be nonzero; checked inline so any malformed
    # encoding fails without revealing where.
  if sep < 10:
    raise newException(ValueError, "decryption error")
  for i in 2 ..< sep:
    if em[i] == 0x00:
      raise newException(ValueError, "decryption error")
  result = newSeq[byte](k - sep - 1)
  for i in 0 ..< result.len: result[i] = em[sep + 1 + i]

proc pkcs1v15Encrypt*(key: RsaPublicKey, msg: openArray[byte]): seq[byte] =
  ## RSAES-PKCS1-v1_5 encrypt (JWA `RSA1_5`).
  let em = pkcs1v15Encode(msg, key.k)
  let m = fromBytesBE(em)
  result = toBytesBE(publicOp(key, m), key.k)

proc pkcs1v15Decrypt*(key: RsaPrivateKey,
                      cipher: openArray[byte]): seq[byte] =
  ## RSAES-PKCS1-v1_5 decrypt. Raises ValueError("decryption error").
  if cipher.len != key.k:
    raise newException(ValueError, "decryption error")
  let c = fromBytesBE(cipher)
  if c >= key.n:
    raise newException(ValueError, "decryption error")
  var em = toBytesBE(privateOpBlinded(key, c), key.k)
  result = pkcs1v15Decode(em)
  wipe(em)

{.pop.}
