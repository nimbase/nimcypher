# BigInt extensions for RSA/ECDSA: byte conversions, prime generation.
#
# Built on `pkg/bigints` (pure Nim, MIT). All private-key operations that
# use these helpers are variable-time; callers needing side-channel
# resistance must add blinding (RSA) or deterministic nonces (ECDSA).
# Randomness always comes from `std/sysrand`, never `std/random`.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/options
import std/sysrand

import bigints

import ./common

export bigints

{.push checks: off.}

# ---------------------------------------------------------------------------
# Bytes <-> BigInt (big-endian, RFC 3447 OS2IP/I2OSP)
# ---------------------------------------------------------------------------

proc fromBytesBE*(bytes: openArray[byte]): BigInt =
  ## OS2IP: interpret big-endian bytes as an unsigned integer.
  ## Empty input yields zero.
  result = initBigInt(0)
  for b in bytes:
    result = (result shl 8) + initBigInt(int(b))

proc byteLen*(x: BigInt): int =
  ## Minimal number of bytes needed to represent `x` (0 -> 0).
  if x == initBigInt(0):
    return 0
  result = (fastLog2(x) + 1 + 7) div 8

proc bitLen*(x: BigInt): int =
  ## Number of bits of `x` (0 -> 0).
  if x == initBigInt(0):
    return 0
  result = fastLog2(x) + 1

proc smallToInt(x: BigInt): int =
  let o = toInt[int](x)
  if o.isNone:
    raise newException(ValueError, "integer out of int range")
  o.get

proc toBytesBE*(x: BigInt, outLen: int): seq[byte] =
  ## I2OSP: encode `x` as exactly `outLen` big-endian bytes.
  ## Raises ValueError if `x` does not fit.
  if x < initBigInt(0):
    raise newException(ValueError, "negative integer cannot be encoded")
  if outLen < 0:
    raise newException(ValueError, "negative output length")
  if outLen == 0:
    if x != initBigInt(0):
      raise newException(ValueError, "integer too large for output")
    return @[]
  if byteLen(x) > outLen:
    raise newException(ValueError, "integer too large for output")
  result = newSeq[byte](outLen)
  var v = x
  let base = initBigInt(256)
  for i in countdown(outLen - 1, 0):
    let qr = divmod(v, base)
    result[i] = byte(smallToInt(qr.r))
    v = qr.q

proc toBytesBETrimmed*(x: BigInt): seq[byte] =
  ## Minimal-length big-endian encoding (0 -> empty, caller decides).
  ## JWK base64urlUInt uses this (with 0 encoded as single 0x00 out-of-band).
  if x == initBigInt(0):
    return @[]
  result = toBytesBE(x, byteLen(x))

# ---------------------------------------------------------------------------
# Random BigInts from the OS CSPRNG
# ---------------------------------------------------------------------------

proc randomBytesSeq*(n: int): seq[byte] =
  if n <= 0:
    return @[]
  let s = urandom(n)
  if s.len != n:
    raise newException(ValueError, "could not read enough bytes from urandom")
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = uint8(s[i])

proc randomBigIntBits*(bits: int, setTopBit = true, odd = false): BigInt =
  ## Random integer with at most `bits` bits. When `setTopBit`, the top
  ## bit is set so the value has exactly `bits` bits. When `odd`, LSB is set.
  if bits <= 0:
    raise newException(ValueError, "bits must be positive")
  let nbytes = (bits + 7) div 8
  var buf = randomBytesSeq(nbytes)
  let excess = nbytes * 8 - bits
  if excess > 0:
    buf[0] = buf[0] and byte(0xFF shr excess)
  if setTopBit:
    buf[0] = buf[0] or byte(1 shl (7 - excess))
  # ensure odd candidates for prime search without extra round-trips
  if odd:
    buf[^1] = buf[^1] or 1
  result = fromBytesBE(buf)
  wipe(buf)

proc randomBigIntBelow*(n: BigInt): BigInt =
  ## Uniform random integer in [1, n-1]. Raises on n <= 1.
  ## Rejection-sampled to avoid modulo bias.
  let one = initBigInt(1)
  if n <= one:
    raise newException(ValueError, "modulus must be > 1")
  let blen = max(byteLen(n - one), 1)
  while true:
    let buf = randomBytesSeq(blen)
    let v = fromBytesBE(buf)
    if v >= one and v < n:
      return v

# ---------------------------------------------------------------------------
# Primality: trial division + Miller-Rabin
# ---------------------------------------------------------------------------

const smallPrimes = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
  71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
  149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
  227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
  307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
  389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
  467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
  571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
  653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
  751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
  853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
  947, 953, 967, 971, 977, 983, 991, 997, 1009,
]

proc mrWitness(n, a, d, nm1: BigInt, s: int): bool =
  ## One Miller-Rabin round. Returns true when `a` proves compositeness.
  let one = initBigInt(1)
  var x = powmod(a, d, n)
  if x == one or x == nm1:
    return false
  for _ in 1 ..< s:
    x = (x * x) mod n
    if x == nm1:
      return false
    if x == one:
      return true
  result = true

proc isProbablePrime*(n: BigInt, rounds = 12): bool =
  ## Miller-Rabin with trial division pre-screen.
  ## The first rounds use small deterministic bases (2, 3, 5, ...), the
  ## rest random bases. With trial division + 12 rounds the error is far
  ## below 2^-80 for >= 256-bit candidates (HAC 4.4); `randomPrime`
  ## passes its own round count through.
  let zero = initBigInt(0)
  let one = initBigInt(1)
  let two = initBigInt(2)
  if n < two:
    return false
  # small-prime check (also catches even numbers)
  for p in [2, 3]:
    let pp = initBigInt(p)
    if n == pp:
      return true
    if (n mod pp) == zero:
      return false
  for p in smallPrimes:
    let pp = initBigInt(p)
    if n == pp:
      return true
    if (n mod pp) == zero:
      return false
  # write n-1 = d * 2^s
  var d = n - one
  var s = 0
  while (d mod two) == zero:
    d = d div two
    inc s
  let nm1 = n - one
  const detBases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
  var done = 0
  for b in detBases:
    if done >= rounds:
      break
    let a = initBigInt(b)
    if a >= nm1:
      continue
    if mrWitness(n, a, d, nm1, s):
      return false
    inc done
  for _ in done ..< rounds:
    # random base a in [2, n-2]
    var a: BigInt
    if n <= initBigInt(4):
      a = two
    else:
      let inner = n - initBigInt(3) # n-3 >= 1
      a = (randomBigIntBelow(inner + one) mod inner) + two
      if a < two or a > n - two:
        a = two
    if mrWitness(n, a, d, nm1, s):
      return false
  result = true

proc randomPrime*(bits: int, rounds = 12): BigInt =
  ## Generate a random `bits`-bit prime (top bit + odd enforced).
  ## NOTE: pure-Nim keygen is slow (tens of seconds for 1024-bit RSA);
  ## JOSE deployments normally import keys (JWK) and generate rarely.
  if bits < 16:
    raise newException(ValueError, "prime size too small")
  while true:
    let cand = randomBigIntBits(bits, setTopBit = true, odd = true)
    # trial division already inside isProbablePrime, but skip even quickly
    if isProbablePrime(cand, rounds):
      return cand

{.pop.}
