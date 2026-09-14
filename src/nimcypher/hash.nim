# High-level hashing API: BLAKE2b, SHA-512, SHA-256, HMAC-SHA-1, HMAC, HKDF.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import nimcypher/algos/blake2b as blakeAlgo
import nimcypher/algos/sha512 as shaAlgo
import nimcypher/algos/sha256 as sha256Algo
import nimcypher/algos/sha384 as sha384Algo
import nimcypher/algos/sha1 as sha1Algo
import nimcypher/algos/hkdf as hkdfAlgo
import nimcypher/hashes/md5 as md5Algo
import nimcypher/hashes/xxhash as xxhAlgo

import ./utils

const
  Blake2bMinDigestSize* = 1
  Blake2bMaxDigestSize* = 64
  Blake2bDefaultDigestSize* = 32
  Blake2bMaxKeySize* = 64
  Sha512DigestSize* = 64
  Sha512BlockSize* = 128
  Sha384DigestSize* = 48
  Sha384BlockSize* = 128
  Sha256DigestSize* = 32
  Sha256BlockSize* = 64
  Sha1DigestSize* = 20
  Sha1BlockSize* = 64
  Md5DigestSize* = 16
  Md5BlockSize* = 64

type
  Sha512Digest* = array[Sha512DigestSize, uint8]
  Sha512Hmac* = array[Sha512DigestSize, uint8]
  Sha384Digest* = array[Sha384DigestSize, uint8]
  Sha384Hmac* = array[Sha384DigestSize, uint8]
  Sha256Digest* = array[Sha256DigestSize, uint8]
  Sha256Hmac* = array[Sha256DigestSize, uint8]
  Sha1Hmac* = array[Sha1DigestSize, uint8]
  Md5Digest* = array[Md5DigestSize, uint8]
  Md5Hmac* = array[Md5DigestSize, uint8]

  Blake2b* = object
    ## Stateful BLAKE2b computation. Update with chunks, then `finish`.
    ctx: blakeAlgo.Blake2bContext
    hashSize: int
    finalized: bool

  Sha512State* = object
    ## Stateful SHA-512 computation.
    ctx: shaAlgo.Sha512Context
    finalized: bool

  Sha512HmacState* = object
    ## Stateful HMAC-SHA-512 computation.
    ctx: shaAlgo.Sha512HmacContext
    finalized: bool

proc ensureHashSize(hashSize: int) {.inline.} =
  if hashSize < Blake2bMinDigestSize or hashSize > Blake2bMaxDigestSize:
    raise newException(ValueError, "BLAKE2b hash size must be in 1..64 bytes")

proc ensureKeySize(keySize: int) {.inline.} =
  if keySize < 1 or keySize > Blake2bMaxKeySize:
    raise newException(ValueError, "BLAKE2b key size must be in 1..64 bytes")

# BLAKE2b (one-shot)
proc blake*(message: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute the BLAKE2b hash of the message (default 32-byte digest).
  ensureHashSize(hashSize)
  result = blakeAlgo.blake2b(message, hashSize)

proc blake*(message: string, hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ensureHashSize(hashSize)
  result = blakeAlgo.blake2b(toBytes(message), hashSize)

proc blakeHex*(message: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): string =
  toHex(blake(message, hashSize))

proc blakeHex*(message: string, hashSize: int = Blake2bDefaultDigestSize): string =
  toHex(blake(message, hashSize))

proc blakeKeyed*(message: openArray[byte], key: openArray[byte],
                 hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute a keyed BLAKE2b hash (MAC).
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result = blakeAlgo.keyedBlake2b(message, key, hashSize)

proc blakeKeyed*(message, key: string,
                 hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result = blakeAlgo.keyedBlake2b(toBytes(message), toBytes(key), hashSize)

proc blakeKeyedHex*(message: openArray[byte], key: openArray[byte],
                    hashSize: int = Blake2bDefaultDigestSize): string =
  toHex(blakeKeyed(message, key, hashSize))

proc blakeKeyedHex*(message, key: string,
                    hashSize: int = Blake2bDefaultDigestSize): string =
  toHex(blakeKeyed(message, key, hashSize))

# BLAKE2b (streaming)
proc initBlake2b*(hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  ensureHashSize(hashSize)
  result.hashSize = hashSize
  result.finalized = false
  blakeAlgo.init(result.ctx, hashSize)

proc initBlake2bKeyed*(key: openArray[byte],
                       hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result.hashSize = hashSize
  result.finalized = false
  blakeAlgo.init(result.ctx, hashSize, key)

proc initBlake2bKeyed*(key: string,
                       hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  initBlake2bKeyed(toBytes(key), hashSize)

proc update*(state: var Blake2b, chunk: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "BLAKE2b context already finalized")
  blakeAlgo.update(state.ctx, chunk)

proc update*(state: var Blake2b, chunk: string) =
  update(state, toBytes(chunk))

proc finish*(state: var Blake2b): seq[byte] =
  if state.finalized:
    raise newException(ValueError, "BLAKE2b context already finalized")
  result = blakeAlgo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Blake2b): string =
  toHex(finish(state))

# SHA-512 (one-shot)
proc sha512*(message: openArray[byte]): Sha512Digest =
  shaAlgo.sha512(message)

proc sha512*(message: string): Sha512Digest =
  shaAlgo.sha512(toBytes(message))

proc sha512Hex*(message: openArray[byte]): string =
  toHex(sha512(message))

proc sha512Hex*(message: string): string =
  toHex(sha512(message))

# SHA-512 (streaming)
proc initSha512*(): Sha512State =
  result.finalized = false
  shaAlgo.init(result.ctx)

proc update*(state: var Sha512State, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "SHA-512 state already finalized")
  shaAlgo.update(state.ctx, message)

proc update*(state: var Sha512State, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha512State): Sha512Digest =
  if state.finalized:
    raise newException(ValueError, "SHA-512 state already finalized")
  result = shaAlgo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Sha512State): string =
  toHex(finish(state))

# HMAC-SHA-512 (one-shot)
proc sha512Hmac*(key, message: openArray[byte]): Sha512Hmac =
  shaAlgo.sha512Hmac(key, message)

proc sha512Hmac*(key, message: string): Sha512Hmac =
  shaAlgo.sha512Hmac(toBytes(key), toBytes(message))

proc sha512HmacHex*(key, message: openArray[byte]): string =
  toHex(sha512Hmac(key, message))

proc sha512HmacHex*(key, message: string): string =
  toHex(sha512Hmac(key, message))

# HMAC-SHA-512 (streaming)
proc initSha512Hmac*(key: openArray[byte]): Sha512HmacState =
  result.finalized = false
  shaAlgo.initHmac(result.ctx, key)

proc initSha512Hmac*(key: string): Sha512HmacState =
  initSha512Hmac(toBytes(key))

proc update*(state: var Sha512HmacState, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-512 state already finalized")
  shaAlgo.update(state.ctx, message)

proc update*(state: var Sha512HmacState, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha512HmacState): Sha512Hmac =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-512 state already finalized")
  result = shaAlgo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Sha512HmacState): string =
  toHex(finish(state))

# HMAC-SHA-1 (one-shot, no streaming)
proc sha1Hmac*(key, message: openArray[byte]): Sha1Hmac =
  sha1Algo.sha1Hmac(key, message)

proc sha1Hmac*(key, message: string): Sha1Hmac =
  sha1Algo.sha1Hmac(toBytes(key), toBytes(message))

proc sha1HmacHex*(key, message: openArray[byte]): string =
  toHex(sha1Hmac(key, message))

proc sha1HmacHex*(key, message: string): string =
  toHex(sha1Hmac(key, message))

# SHA-256 (one-shot)
proc sha256*(message: openArray[byte]): Sha256Digest =
  sha256Algo.sha256(message)

proc sha256*(message: string): Sha256Digest =
  sha256Algo.sha256(toBytes(message))

proc sha256Hex*(message: openArray[byte]): string =
  toHex(sha256(message))

proc sha256Hex*(message: string): string =
  toHex(sha256(message))

# SHA-256 (streaming)
type
  Sha256State* = object
    ctx: sha256Algo.Sha256Context
    finalized: bool

  Sha256HmacState* = object
    ctx: sha256Algo.Sha256HmacContext
    finalized: bool

proc initSha256*(): Sha256State =
  result.finalized = false
  sha256Algo.init(result.ctx)

proc update*(state: var Sha256State, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "SHA-256 state already finalized")
  sha256Algo.update(state.ctx, message)

proc update*(state: var Sha256State, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha256State): Sha256Digest =
  if state.finalized:
    raise newException(ValueError, "SHA-256 state already finalized")
  result = sha256Algo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Sha256State): string =
  toHex(finish(state))

# HMAC-SHA-256 (one-shot + streaming)
proc sha256Hmac*(key, message: openArray[byte]): Sha256Hmac =
  sha256Algo.sha256Hmac(key, message)

proc sha256Hmac*(key, message: string): Sha256Hmac =
  sha256Algo.sha256Hmac(toBytes(key), toBytes(message))

proc sha256HmacHex*(key, message: openArray[byte]): string =
  toHex(sha256Hmac(key, message))

proc sha256HmacHex*(key, message: string): string =
  toHex(sha256Hmac(key, message))

proc initSha256Hmac*(key: openArray[byte]): Sha256HmacState =
  result.finalized = false
  sha256Algo.initHmac(result.ctx, key)

proc initSha256Hmac*(key: string): Sha256HmacState =
  initSha256Hmac(toBytes(key))

proc update*(state: var Sha256HmacState, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-256 state already finalized")
  sha256Algo.update(state.ctx, message)

proc update*(state: var Sha256HmacState, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha256HmacState): Sha256Hmac =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-256 state already finalized")
  result = sha256Algo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Sha256HmacState): string =
  toHex(finish(state))

# SHA-384 (one-shot)
proc sha384*(message: openArray[byte]): Sha384Digest =
  let d = sha384Algo.sha384(message)
  for i in 0 ..< Sha384DigestSize: result[i] = d[i]

proc sha384*(message: string): Sha384Digest =
  sha384(toBytes(message))

proc sha384Hex*(message: openArray[byte]): string =
  toHex(sha384(message))

proc sha384Hex*(message: string): string =
  toHex(sha384(message))

# SHA-384 (streaming)
type
  Sha384State* = object
    ctx: shaAlgo.Sha512Context
    finalized: bool

  Sha384HmacState* = object
    ctx: sha384Algo.Sha384HmacContext
    finalized: bool

proc initSha384*(): Sha384State =
  result.finalized = false
  sha384Algo.init384(result.ctx)

proc update*(state: var Sha384State, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "SHA-384 state already finalized")
  shaAlgo.update(state.ctx, message)

proc update*(state: var Sha384State, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha384State): Sha384Digest =
  if state.finalized:
    raise newException(ValueError, "SHA-384 state already finalized")
  let full = shaAlgo.final(state.ctx)
  for i in 0 ..< Sha384DigestSize: result[i] = full[i]
  state.finalized = true

proc finishHex*(state: var Sha384State): string =
  toHex(finish(state))

# HMAC-SHA-384 (one-shot + streaming)
proc sha384Hmac*(key, message: openArray[byte]): Sha384Hmac =
  let m = sha384Algo.sha384Hmac(key, message)
  for i in 0 ..< Sha384DigestSize: result[i] = m[i]

proc sha384Hmac*(key, message: string): Sha384Hmac =
  sha384Hmac(toBytes(key), toBytes(message))

proc sha384HmacHex*(key, message: openArray[byte]): string =
  toHex(sha384Hmac(key, message))

proc sha384HmacHex*(key, message: string): string =
  toHex(sha384Hmac(key, message))

proc initSha384Hmac*(key: openArray[byte]): Sha384HmacState =
  result.finalized = false
  sha384Algo.initHmac384(result.ctx, key)

proc initSha384Hmac*(key: string): Sha384HmacState =
  initSha384Hmac(toBytes(key))

proc update*(state: var Sha384HmacState, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-384 state already finalized")
  sha384Algo.update(state.ctx, message)

proc update*(state: var Sha384HmacState, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Sha384HmacState): Sha384Hmac =
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA-384 state already finalized")
  let m = sha384Algo.final(state.ctx)
  for i in 0 ..< Sha384DigestSize: result[i] = m[i]
  state.finalized = true

proc finishHex*(state: var Sha384HmacState): string =
  toHex(finish(state))

# HKDF-SHA-512

const
  HkdfMaxOkmLen* = 255 * Sha512DigestSize # RFC 5869: at most 255 blocks
  HkdfSha256MaxOkmLen* = 255 * Sha256DigestSize

proc ensureHkdfLength(okmLen: Natural) {.inline.} =
  if okmLen > HkdfMaxOkmLen:
    raise newException(ValueError,
      "HKDF output too large: at most " & $HkdfMaxOkmLen & " bytes")

proc hkdfSha512*(ikm, salt, info: openArray[byte], okmLen: Natural): seq[byte] =
  ## Derive output keying material of `okmLen` bytes with HKDF-SHA-512.
  ensureHkdfLength(okmLen)
  result = hkdfAlgo.sha512Hkdf(ikm, salt, info, okmLen)

proc hkdfSha512*(ikm, salt, info: string, okmLen: Natural): seq[byte] =
  hkdfSha512(toBytes(ikm), toBytes(salt), toBytes(info), okmLen)

proc hkdfExpandSha512*(prk, info: openArray[byte], okmLen: Natural): seq[byte] =
  ## Expand a pseudo-random key with HKDF-SHA-512.
  ensureHkdfLength(okmLen)
  result = hkdfAlgo.sha512HkdfExpand(prk, info, okmLen)

proc hkdfExpandSha512*(prk, info: string, okmLen: Natural): seq[byte] =
  hkdfExpandSha512(toBytes(prk), toBytes(info), okmLen)

proc hkdfSha512*[N: static[int]](ikm, salt, info: openArray[byte]): array[N, uint8] =
  ## Derive a fixed-size output key of N bytes with HKDF-SHA-512.
  let okm = hkdfSha512(ikm, salt, info, N)
  for i in 0 ..< N:
    result[i] = okm[i]

proc hkdfExpandSha512*[N: static[int]](prk, info: openArray[byte]): array[N, uint8] =
  let okm = hkdfExpandSha512(prk, info, N)
  for i in 0 ..< N:
    result[i] = okm[i]

proc ensureHkdfSha256Length(okmLen: Natural) {.inline.} =
  if okmLen > HkdfSha256MaxOkmLen:
    raise newException(ValueError,
      "HKDF-SHA-256 output too large: at most " & $HkdfSha256MaxOkmLen & " bytes")

proc hkdfSha256*(ikm, salt, info: openArray[byte], okmLen: Natural): seq[byte] =
  ## Derive output keying material of `okmLen` bytes with HKDF-SHA-256.
  ensureHkdfSha256Length(okmLen)
  result = hkdfAlgo.sha256Hkdf(ikm, salt, info, okmLen)

proc hkdfSha256*(ikm, salt, info: string, okmLen: Natural): seq[byte] =
  hkdfSha256(toBytes(ikm), toBytes(salt), toBytes(info), okmLen)

proc hkdfExpandSha256*(prk, info: openArray[byte], okmLen: Natural): seq[byte] =
  ensureHkdfSha256Length(okmLen)
  result = hkdfAlgo.sha256HkdfExpand(prk, info, okmLen)

proc hkdfExpandSha256*(prk, info: string, okmLen: Natural): seq[byte] =
  hkdfExpandSha256(toBytes(prk), toBytes(info), okmLen)

proc hkdfSha256*[N: static[int]](ikm, salt, info: openArray[byte]): array[N, uint8] =
  let okm = hkdfSha256(ikm, salt, info, N)
  for i in 0 ..< N:
    result[i] = okm[i]

proc hkdfExpandSha256*[N: static[int]](prk, info: openArray[byte]): array[N, uint8] =
  let okm = hkdfExpandSha256(prk, info, N)
  for i in 0 ..< N:
    result[i] = okm[i]

# constant-time digest comparison
proc verifyDigest*(a, b: openArray[byte]): bool =
  ## Constant-time comparison of two digests.
  if a.len != b.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  result = diff == 0

# MD5 (one-shot + streaming). Broken: legacy interop only, do not use
# in new designs.

type
  Md5State* = object
    ctx: md5Algo.Md5Context
    finalized: bool

  Md5HmacState* = object
    ctx: md5Algo.Md5HmacContext
    finalized: bool

proc md5*(message: openArray[byte]): Md5Digest =
  md5Algo.md5(message)

proc md5*(message: string): Md5Digest =
  md5Algo.md5(toBytes(message))

proc md5Hex*(message: openArray[byte]): string =
  toHex(md5(message))

proc md5Hex*(message: string): string =
  toHex(md5(message))

proc initMd5*(): Md5State =
  result.finalized = false
  md5Algo.init(result.ctx)

proc update*(state: var Md5State, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "MD5 state already finalized")
  md5Algo.update(state.ctx, message)

proc update*(state: var Md5State, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Md5State): Md5Digest =
  if state.finalized:
    raise newException(ValueError, "MD5 state already finalized")
  result = md5Algo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Md5State): string =
  toHex(finish(state))

proc md5Hmac*(key, message: openArray[byte]): Md5Hmac =
  md5Algo.md5Hmac(key, message)

proc md5Hmac*(key, message: string): Md5Hmac =
  md5Algo.md5Hmac(toBytes(key), toBytes(message))

proc md5HmacHex*(key, message: openArray[byte]): string =
  toHex(md5Hmac(key, message))

proc md5HmacHex*(key, message: string): string =
  toHex(md5Hmac(key, message))

proc initMd5Hmac*(key: openArray[byte]): Md5HmacState =
  result.finalized = false
  md5Algo.initHmac(result.ctx, key)

proc initMd5Hmac*(key: string): Md5HmacState =
  initMd5Hmac(toBytes(key))

proc update*(state: var Md5HmacState, message: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "HMAC-MD5 state already finalized")
  md5Algo.update(state.ctx, message)

proc update*(state: var Md5HmacState, message: string) =
  update(state, toBytes(message))

proc finish*(state: var Md5HmacState): Md5Hmac =
  if state.finalized:
    raise newException(ValueError, "HMAC-MD5 state already finalized")
  result = md5Algo.final(state.ctx)
  state.finalized = true

proc finishHex*(state: var Md5HmacState): string =
  toHex(finish(state))

# xxHash (one-shot + streaming). Non-cryptographic: checksums and hash
# tables only, never signatures, MACs, or password hashing.

proc xxh32Be(v: uint32): array[4, uint8] =
  result[0] = uint8(v shr 24)
  result[1] = uint8(v shr 16)
  result[2] = uint8(v shr 8)
  result[3] = uint8(v)

proc xxh64Be(v: uint64): array[8, uint8] =
  for i in 0 ..< 8:
    result[i] = uint8(v shr (56 - 8 * i))

type
  Xxh32* = object
    ctx: xxhAlgo.Xxh32State
    finalized: bool

  Xxh64* = object
    ctx: xxhAlgo.Xxh64State
    finalized: bool

  Xxh3_64* = object
    ctx: xxhAlgo.Xxh3State
    finalized: bool

  Xxh3_128* = object
    ctx: xxhAlgo.Xxh3State
    finalized: bool

proc xxh32*(data: openArray[byte], seed: uint32 = 0): uint32 =
  xxhAlgo.xxh32(data, seed)

proc xxh32*(data: string, seed: uint32 = 0): uint32 =
  xxhAlgo.xxh32(toBytes(data), seed)

proc xxh32Hex*(data: openArray[byte], seed: uint32 = 0): string =
  toHex(xxh32Be(xxh32(data, seed)))

proc xxh32Hex*(data: string, seed: uint32 = 0): string =
  toHex(xxh32Be(xxh32(data, seed)))

proc initXxh32*(seed: uint32 = 0): Xxh32 =
  result.finalized = false
  xxhAlgo.reset(result.ctx, seed)

proc update*(state: var Xxh32, chunk: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "XXH32 state already finalized")
  xxhAlgo.update(state.ctx, chunk)

proc update*(state: var Xxh32, chunk: string) =
  update(state, toBytes(chunk))

proc finish*(state: var Xxh32): uint32 =
  if state.finalized:
    raise newException(ValueError, "XXH32 state already finalized")
  result = xxhAlgo.digest(state.ctx)
  state.finalized = true

proc finishHex*(state: var Xxh32): string =
  toHex(xxh32Be(finish(state)))

proc xxh64*(data: openArray[byte], seed: uint64 = 0): uint64 =
  xxhAlgo.xxh64(data, seed)

proc xxh64*(data: string, seed: uint64 = 0): uint64 =
  xxhAlgo.xxh64(toBytes(data), seed)

proc xxh64Hex*(data: openArray[byte], seed: uint64 = 0): string =
  toHex(xxh64Be(xxh64(data, seed)))

proc xxh64Hex*(data: string, seed: uint64 = 0): string =
  toHex(xxh64Be(xxh64(data, seed)))

proc initXxh64*(seed: uint64 = 0): Xxh64 =
  result.finalized = false
  xxhAlgo.reset(result.ctx, seed)

proc update*(state: var Xxh64, chunk: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "XXH64 state already finalized")
  xxhAlgo.update(state.ctx, chunk)

proc update*(state: var Xxh64, chunk: string) =
  update(state, toBytes(chunk))

proc finish*(state: var Xxh64): uint64 =
  if state.finalized:
    raise newException(ValueError, "XXH64 state already finalized")
  result = xxhAlgo.digest(state.ctx)
  state.finalized = true

proc finishHex*(state: var Xxh64): string =
  toHex(xxh64Be(finish(state)))

proc xxh3_64bits*(data: openArray[byte], seed: uint64 = 0): uint64 =
  xxhAlgo.xxh3_64bits_withSeed(data, seed)

proc xxh3_64bits*(data: string, seed: uint64 = 0): uint64 =
  xxhAlgo.xxh3_64bits_withSeed(toBytes(data), seed)

proc xxh3_64bitsHex*(data: openArray[byte], seed: uint64 = 0): string =
  toHex(xxh64Be(xxh3_64bits(data, seed)))

proc xxh3_64bitsHex*(data: string, seed: uint64 = 0): string =
  toHex(xxh64Be(xxh3_64bits(data, seed)))

proc initXxh3_64*(seed: uint64 = 0): Xxh3_64 =
  result.finalized = false
  xxhAlgo.resetXxh3(result.ctx, xxhAlgo.xxh3_64, seed)

proc update*(state: var Xxh3_64, chunk: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "XXH3-64 state already finalized")
  xxhAlgo.update(state.ctx, chunk)

proc update*(state: var Xxh3_64, chunk: string) =
  update(state, toBytes(chunk))

proc finish*(state: var Xxh3_64): uint64 =
  if state.finalized:
    raise newException(ValueError, "XXH3-64 state already finalized")
  result = xxhAlgo.digest64(state.ctx)
  state.finalized = true

proc finishHex*(state: var Xxh3_64): string =
  toHex(xxh64Be(finish(state)))

proc xxh128*(data: openArray[byte], seed: uint64 = 0): xxhAlgo.Xxh128 =
  xxhAlgo.xxh128(data, seed)

proc xxh128*(data: string, seed: uint64 = 0): xxhAlgo.Xxh128 =
  xxhAlgo.xxh128(toBytes(data), seed)

proc xxh128Hex*(data: openArray[byte], seed: uint64 = 0): string =
  let h = xxh128(data, seed)
  toHex(xxh64Be(h.hi)) & toHex(xxh64Be(h.lo))

proc xxh128Hex*(data: string, seed: uint64 = 0): string =
  let h = xxh128(data, seed)
  toHex(xxh64Be(h.hi)) & toHex(xxh64Be(h.lo))

proc initXxh3_128*(seed: uint64 = 0): Xxh3_128 =
  result.finalized = false
  xxhAlgo.resetXxh3(result.ctx, xxhAlgo.xxh3_128, seed)

proc update*(state: var Xxh3_128, chunk: openArray[byte]) =
  if state.finalized:
    raise newException(ValueError, "XXH3-128 state already finalized")
  xxhAlgo.update(state.ctx, chunk)

proc update*(state: var Xxh3_128, chunk: string) =
  update(state, toBytes(chunk))

proc finish*(state: var Xxh3_128): xxhAlgo.Xxh128 =
  if state.finalized:
    raise newException(ValueError, "XXH3-128 state already finalized")
  result = xxhAlgo.digest128(state.ctx)
  state.finalized = true

proc finishHex*(state: var Xxh3_128): string =
  let h = finish(state)
  toHex(xxh64Be(h.hi)) & toHex(xxh64Be(h.lo))
