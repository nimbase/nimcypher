# Common utilities for the Monocypher port.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

{.push checks: off.}

const
  # 256 bits of zeroes, used as a "null" plaintext buffer.
  zeroBuf* = block:
    var z: array[128, byte]
    z

type BytePtr* = ptr UncheckedArray[byte]

proc `+`*(p: BytePtr, n: int): BytePtr =
  result = cast[BytePtr](cast[uint](p) + uint(n))

proc load24Le*(s: BytePtr): uint32 {.inline.} =
  result = (uint32(s[0])) or (uint32(s[1]) shl 8) or (uint32(s[2]) shl 16)

proc load32Le*(s: BytePtr): uint32 {.inline.} =
  result = (uint32(s[0]) shl 0) or (uint32(s[1]) shl 8) or
           (uint32(s[2]) shl 16) or (uint32(s[3]) shl 24)

proc load64Le*(s: BytePtr): uint64 {.inline.} =
  result = uint64(load32Le(s)) or (uint64(load32Le(s + 4)) shl 32)

proc store32Le*(outp: BytePtr, inp: uint32) {.inline.} =
  outp[0] = byte(inp)
  outp[1] = byte(inp shr 8)
  outp[2] = byte(inp shr 16)
  outp[3] = byte(inp shr 24)

proc store64Le*(outp: BytePtr, inp: uint64) {.inline.} =
  store32Le(outp, uint32(inp))
  store32Le(outp + 4, uint32(inp shr 32))

proc load32LeBuf*(dst: var openArray[uint32], src: BytePtr, size: int) {.inline.} =
  for i in 0 ..< size:
    dst[i] = load32Le(src + i * 4)

proc load64LeBuf*(dst: var openArray[uint64], src: BytePtr, size: int) {.inline.} =
  for i in 0 ..< size:
    dst[i] = load64Le(src + i * 8)

proc store32LeBuf*(dst: BytePtr, src: openArray[uint32], size: int) {.inline.} =
  for i in 0 ..< size:
    store32Le(dst + i * 4, src[i])

proc store64LeBuf*(dst: BytePtr, src: openArray[uint64], size: int) {.inline.} =
  for i in 0 ..< size:
    store64Le(dst + i * 8, src[i])

proc rotr64*(x: uint64, n: uint64): uint64 {.inline.} =
  result = (x shr n) or (x shl (64 - n))

proc rotl32*(x: uint32, n: uint32): uint32 {.inline.} =
  result = (x shl n) or (x shr (32 - n))

# Returns the smallest positive integer y such that
# (x + y) mod pow_2 == 0. Basically, y is the "gap" missing to align x.
# Only works when pow_2 is a power of 2.
proc gap*(x, pow_2: int): int {.inline.} =
  result = (not x + 1) and (pow_2 - 1)

proc neq0*(diff: uint64): int32 =
  # constant time comparison to zero: returns -1 if diff != 0, 0 otherwise
  let half = (diff shr 32) or uint64(uint32(diff))  # half < 2^32
  let eq0 = 1'u64 and ((half - 1) shr 32)          # half == 0 ? 1 : 0
  result = int32(eq0) - 1

proc x16(a, b: BytePtr): uint64 =
  result = (load64Le(a) xor load64Le(b)) or
           (load64Le(a + 8) xor load64Le(b + 8))

proc x32(a, b: BytePtr): uint64 =
  result = x16(a, b) or x16(a + 16, b + 16)

proc x64(a, b: BytePtr): uint64 =
  result = x32(a, b) or x32(a + 32, b + 32)

proc constantTimeEqual*(a, b: openArray[byte]): bool =
  ## Compare two buffers in constant time.
  ## Returns true if they are equal, false otherwise.
  if a.len != b.len:
    return false
  if a.len == 0:
    return true
  let pa = cast[BytePtr](unsafeAddr a[0])
  let pb = cast[BytePtr](unsafeAddr b[0])
  if a.len == 16:
    return neq0(x16(pa, pb)) == 0
  if a.len == 32:
    return neq0(x32(pa, pb)) == 0
  if a.len == 64:
    return neq0(x64(pa, pb)) == 0
  var diff: uint64 = 0
  for i in 0 ..< a.len:
    diff = diff or (uint64(a[i]) xor uint64(b[i]))
  result = neq0(diff) == 0

proc wipe*(secret: var openArray[byte]) =
  ## Erase the contents of a buffer (constant time, not optimized away).
  if secret.len == 0:
    return
  let p = cast[BytePtr](unsafeAddr secret[0])
  for i in 0 ..< secret.len:
    p[i] = 0
  {.emit: """asm volatile("" ::: "memory");""".}

proc wipe*[T](x: var T) =
  ## Erase any type's memory in constant time.
  when T is seq or T is string:
    # wipe the backing data, not the sequence/string header
    if x.len > 0:
      wipe(x.toOpenArray(0, x.len - 1))
  else:
    var p = cast[BytePtr](unsafeAddr x)
    for i in 0 ..< sizeof(T):
      p[i] = 0
    {.emit: """asm volatile("" ::: "memory");""".}

{.pop.}
