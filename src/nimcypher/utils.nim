# High-level utilities: byte types, hex encoding, random bytes.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import std/[strutils, sysrand]

import nimcypher/algos/common as commonAlgo

proc constantTimeEqual*(a, b: openArray[byte]): bool =
  ## Compare two buffers in constant time. Returns true if equal.
  commonAlgo.constantTimeEqual(a, b)

proc wipe*(secret: var openArray[byte]) =
  ## Erase the contents of a buffer (constant time, not optimized away).
  commonAlgo.wipe(secret)

type
  Key32* = array[32, uint8]
  Nonce24* = array[24, uint8]
  Mac16* = array[16, uint8]
  RandomBytes* = array[16, uint8]
  Seed32* = array[32, uint8]
  PublicKey* = array[32, uint8]
  SecretKey* = array[64, uint8]
  Signature* = array[64, uint8]

proc toHex*(data: openArray[byte]): string =
  ## Convert binary data to a lowercase hex string.
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(toHex(b, 2))

proc fromHex*[N: static int, T](s: string): array[N, T] =
  ## Convert a hex string back to an array of bytes of type T.
  if s.len != N * 2:
    raise newException(ValueError, "invalid hex length")
  for i in 0 ..< N:
    let a = i * 2
    let b = a + 1
    result[i] = T(parseHexInt(s[a .. b]))

proc randomBytes*[N: static int]: array[N, uint8] =
  ## Generate N random bytes using urandom.
  let bytes = urandom(N)
  if bytes.len != N:
    raise newException(ValueError, "Could not read enough bytes from urandom")
  for i in 0 ..< N:
    result[i] = uint8(bytes[i])

proc generateSalt*(len: static int = 16): RandomBytes =
  ## Generate a random salt (default 16 bytes).
  randomBytes[len]()

proc toBytes*(s: string): seq[byte] =
  ## Convert a string to bytes.
  for c in s:
    result.add(byte(c))

proc toArray*[N: static int](b: openArray[byte]): array[N, uint8] =
  ## Convert a byte buffer to a fixed-size array.
  doAssert b.len == N
  for i in 0 ..< N:
    result[i] = b[i]

proc toString*(data: openArray[byte]): string =
  ## Convert bytes to a string.
  result = newStringOfCap(data.len)
  for b in data:
    result.add(char(b))
