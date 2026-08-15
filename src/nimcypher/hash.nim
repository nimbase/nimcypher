# High-level hashing API: BLAKE2b, SHA-512, HMAC, HKDF.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import nimcypher/algos/blake2b as blakeAlgo
import nimcypher/algos/sha512 as shaAlgo
import nimcypher/algos/hkdf as hkdfAlgo

import ./utils

const
  Blake2bMinDigestSize* = 1
  Blake2bMaxDigestSize* = 64
  Blake2bDefaultDigestSize* = 32
  Blake2bMaxKeySize* = 64
  Sha512DigestSize* = 64
  Sha512BlockSize* = 128

type
  Sha512Digest* = array[Sha512DigestSize, uint8]
  Sha512Hmac* = array[Sha512DigestSize, uint8]

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

# HKDF-SHA-512
proc hkdfSha512*(ikm, salt, info: openArray[byte], okmLen: Natural): seq[byte] =
  ## Derive output keying material of `okmLen` bytes with HKDF-SHA-512.
  result = hkdfAlgo.sha512Hkdf(ikm, salt, info, okmLen)

proc hkdfSha512*(ikm, salt, info: string, okmLen: Natural): seq[byte] =
  hkdfSha512(toBytes(ikm), toBytes(salt), toBytes(info), okmLen)

proc hkdfExpandSha512*(prk, info: openArray[byte], okmLen: Natural): seq[byte] =
  ## Expand a pseudo-random key with HKDF-SHA-512.
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

# constant-time digest comparison
proc verifyDigest*(a, b: openArray[byte]): bool =
  ## Constant-time comparison of two digests.
  if a.len != b.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  result = diff == 0
