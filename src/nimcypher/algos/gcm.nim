# GCM authenticated encryption (NIST SP 800-38D) over the NimCypher
# constant-time AES core.
#
# GHASH operates in GF(2^128) with no lookup tables: the field
# multiplication is a port of BearSSL's `ghash_ctmul64` (Thomas Pornin,
# MIT), which stays constant-time on every input. AES-GCTR runs through
# the fixsliced AES kernel from `./aes`.
#
# Streaming notes: like most GCM implementations, authentication covers the
# whole message and is only decided by `finishDec`. Chunked decryption
# releases plaintext before verification, so callers must not use it until
# `finishDec` returns true. The one-shot `gcmUnlock` enforces this by only
# returning plaintext on success.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/options

import ./common
import ./aes

when defined(features.nimcypher.nimsimd) and defined(amd64):
  import ./internal/ghash_simd

{.push checks: off.}

const gcmBlockSize = 16

# ---------------------------------------------------------------------------
# Constant-time GHASH (BearSSL ghash_ctmul64).
#
# Blocks live as two big-endian 64-bit halves (y0 = low half). The 128-bit
# carry-less product is built from four 64x64 bit-sliced multipliers plus a
# Karatsuba half computed on bit-reversed operands.
# ---------------------------------------------------------------------------

proc bmul64(x, y: uint64): uint64 {.inline.} =
  ## Carry-less product of two polynomials with 16-bit coefficients,
  ## interleaved four ways so plain integer multiplies stay carry-safe.
  let x0 = x and 0x1111111111111111'u64
  let x1 = x and 0x2222222222222222'u64
  let x2 = x and 0x4444444444444444'u64
  let x3 = x and 0x8888888888888888'u64
  let y0 = y and 0x1111111111111111'u64
  let y1 = y and 0x2222222222222222'u64
  let y2 = y and 0x4444444444444444'u64
  let y3 = y and 0x8888888888888888'u64
  var z0 = (x0 * y0) xor (x1 * y3) xor (x2 * y2) xor (x3 * y1)
  var z1 = (x0 * y1) xor (x1 * y0) xor (x2 * y3) xor (x3 * y2)
  var z2 = (x0 * y2) xor (x1 * y1) xor (x2 * y0) xor (x3 * y3)
  var z3 = (x0 * y3) xor (x1 * y2) xor (x2 * y1) xor (x3 * y0)
  z0 = z0 and 0x1111111111111111'u64
  z1 = z1 and 0x2222222222222222'u64
  z2 = z2 and 0x4444444444444444'u64
  z3 = z3 and 0x8888888888888888'u64
  result = z0 or z1 or z2 or z3

func rev64(xArg: uint64): uint64 {.inline.} =
  var x = xArg
  template rms(m: uint64, s: int) =
    x = ((x and m) shl s) or ((x shr s) and m)
  rms(0x5555555555555555'u64, 1)
  rms(0x3333333333333333'u64, 2)
  rms(0x0F0F0F0F0F0F0F0F'u64, 4)
  rms(0x00FF00FF00FF00FF'u64, 8)
  rms(0x0000FFFF0000FFFF'u64, 16)
  result = (x shl 32) or (x shr 32)

proc load64Be(s: BytePtr): uint64 {.inline.} =
  result = 0'u64
  for i in 0 ..< 8:
    result = (result shl 8) or uint64(s[i])

proc store64Be(outp: BytePtr, x: uint64) {.inline.} =
  for i in 0 ..< 8:
    outp[i] = byte(x shr (8 * (7 - i)))

proc ghashFoldScalar*(acc: var array[16, byte], hBlock: array[16, byte],
                    src: BytePtr) =
  ## acc = (acc xor block) * H mod (x^128 + x^7 + x^2 + x + 1)
  ## (constant-time scalar reference kernel)
  var y1 = load64Be(cast[BytePtr](addr acc[0]))
  var y0 = load64Be(cast[BytePtr](addr acc[8]))
  y1 = y1 xor load64Be(src)
  y0 = y0 xor load64Be(src + 8)
  let h1 = load64Be(cast[BytePtr](addr hBlock[0]))
  let h0 = load64Be(cast[BytePtr](addr hBlock[8]))
  let yr0 = rev64(y0)
  let yr1 = rev64(y1)
  let y2 = y0 xor y1
  let y2r = yr0 xor yr1
  let h0r = rev64(h0)
  let h1r = rev64(h1)
  let h2 = h0 xor h1
  let h2r = h0r xor h1r
  var z0 = bmul64(y0, h0)
  var z1 = bmul64(y1, h1)
  var z2 = bmul64(y2, h2)
  var z0h = bmul64(yr0, h0r)
  var z1h = bmul64(yr1, h1r)
  var z2h = bmul64(y2r, h2r)
  z2 = z2 xor z0 xor z1
  z2h = z2h xor z0h xor z1h
  z0h = rev64(z0h) shr 1
  z1h = rev64(z1h) shr 1
  z2h = rev64(z2h) shr 1
  var v0 = z0
  var v1 = z0h xor z2
  var v2 = z1 xor z2h
  var v3 = z1h
  v3 = (v3 shl 1) or (v2 shr 63)
  v2 = (v2 shl 1) or (v1 shr 63)
  v1 = (v1 shl 1) or (v0 shr 63)
  v0 = v0 shl 1
  v2 = v2 xor v0 xor (v0 shr 1) xor (v0 shr 2) xor (v0 shr 7)
  v1 = v1 xor (v0 shl 63) xor (v0 shl 62) xor (v0 shl 57)
  v3 = v3 xor v1 xor (v1 shr 1) xor (v1 shr 2) xor (v1 shr 7)
  v2 = v2 xor (v1 shl 63) xor (v1 shl 62) xor (v1 shl 57)
  store64Be(cast[BytePtr](addr acc[0]), v3)
  store64Be(cast[BytePtr](addr acc[8]), v2)

when defined(features.nimcypher.nimsimd) and defined(amd64):
  proc ghashFold*(acc: var array[16, byte], h: array[16, byte],
                  src: BytePtr) {.inline.} =
    ghashFoldClmul(acc, h, src)
else:
  proc ghashFold*(acc: var array[16, byte], h: array[16, byte],
                  src: BytePtr) {.inline.} =
    ghashFoldScalar(acc, h, src)

# ---------------------------------------------------------------------------
# GCM context.
# ---------------------------------------------------------------------------

type
  GcmContext* = object
    aes: AesContext
    hBlock: array[16, byte] # GHASH key block H = E_K(0^128)
    acc*: array[16, byte]   # GHASH accumulator (big-endian block)
    ctr: array[16, byte]    # GCTR counter block (starts at inc32(J0))
    j0: array[16, byte]     # pre-counter block (tag mask source)
    kbuf: array[16, byte]   # partially consumed keystream block
    kused: int
    buf: array[16, byte]    # pending GHASH block (AAD or ciphertext)
    bufLen: int
    aadLen*: uint64         # total associated-data bytes absorbed
    ctLen*: uint64          # total ciphertext bytes absorbed
    inAad: bool             # still absorbing associated data
    forceScalar: bool       # benchmarking hook: use the scalar GHASH

proc inc32(b: var array[16, byte]) {.inline.} =
  # increment the last 32 bits, big-endian, modulo 2^32
  var v = (uint32(b[12]) shl 24) or (uint32(b[13]) shl 16) or
          (uint32(b[14]) shl 8) or uint32(b[15])
  v += 1
  b[12] = byte(v shr 24)
  b[13] = byte(v shr 16)
  b[14] = byte(v shr 8)
  b[15] = byte(v)

proc fold(ctx: var GcmContext, p: BytePtr) {.inline.} =
  if ctx.forceScalar:
    ghashFoldScalar(ctx.acc, ctx.hBlock, p)
  else:
    ghashFold(ctx.acc, ctx.hBlock, p)

proc absorb(ctx: var GcmContext, p: BytePtr, n: int) =
  ## Feed whole/partial blocks into GHASH (zero-padding the final tail is
  ## done by `flushBuf`/the length block instead, per the spec).
  var pp = p
  var left = n
  while left > 0:
    if ctx.bufLen > 0:
      let take = min(gcmBlockSize - ctx.bufLen, left)
      copyMem(addr ctx.buf[ctx.bufLen], pp, take)
      ctx.bufLen += take
      pp = pp + take
      left -= take
      if ctx.bufLen == gcmBlockSize:
        ctx.fold(cast[BytePtr](addr ctx.buf[0]))
        ctx.bufLen = 0
    else:
      while left >= gcmBlockSize:
        ctx.fold(pp)
        pp = pp + gcmBlockSize
        left -= gcmBlockSize
      if left > 0:
        copyMem(addr ctx.buf[0], pp, left)
        ctx.bufLen = left
        left = 0

proc flushAad(ctx: var GcmContext) =
  ## Zero-pad and fold any pending AAD tail before switching to data.
  if ctx.inAad:
    if ctx.bufLen > 0:
      zeroMem(addr ctx.buf[ctx.bufLen], gcmBlockSize - ctx.bufLen)
      ctx.fold(cast[BytePtr](addr ctx.buf[0]))
      ctx.bufLen = 0
    ctx.inAad = false

proc computeJ0(ctx: var GcmContext, iv: openArray[byte]): array[16, byte] =
  ## J0 for non-96-bit IVs: GHASH_H(IV || pad || [len(IV)]_64)
  var acc: array[16, byte]
  zeroMem(addr acc[0], 16)
  let n = iv.len
  var i = 0
  while i + gcmBlockSize <= n:
    ghashFold(acc, ctx.hBlock, cast[BytePtr](unsafeAddr iv[i]))
    i += gcmBlockSize
  if i < n:
    var tmp: array[16, byte]
    copyMem(addr tmp[0], unsafeAddr iv[i], n - i)
    ghashFold(acc, ctx.hBlock, cast[BytePtr](addr tmp[0]))
    wipe(tmp)
  var lens: array[16, byte]
  store64Be(cast[BytePtr](addr lens[8]), uint64(n) * 8)
  ghashFold(acc, ctx.hBlock, cast[BytePtr](addr lens[0]))
  wipe(lens)
  result = acc

proc initGcm*(ctx: var GcmContext, key: openArray[byte],
              iv: openArray[byte], forceScalar = false) =
  ## Initialize a GCM context. Raises ValueError on an invalid key length
  ## or an empty IV.
  if iv.len == 0:
    raise newException(ValueError, "GCM IV must not be empty")
  initAes(ctx.aes, key)
  var zero: array[16, byte]
  var h: array[16, byte]
  encryptBlockRaw(ctx.aes, cast[BytePtr](addr h[0]),
                  cast[BytePtr](addr zero[0]))
  ctx.hBlock = h
  wipe(h)
  zeroMem(addr ctx.acc[0], 16)
  ctx.bufLen = 0
  ctx.kused = 16 # force keystream generation on first update
  ctx.aadLen = 0
  ctx.ctLen = 0
  ctx.inAad = true
  ctx.forceScalar = forceScalar
  if iv.len == 12:
    copyMem(addr ctx.j0[0], unsafeAddr iv[0], 12)
    ctx.j0[12] = 0
    ctx.j0[13] = 0
    ctx.j0[14] = 0
    ctx.j0[15] = 1
  else:
    ctx.j0 = computeJ0(ctx, iv)
  ctx.ctr = ctx.j0
  inc32(ctx.ctr) # GCTR starts at inc32(J0); the tag mask uses J0 itself

proc gcmAddAad*(ctx: var GcmContext, ad: openArray[byte]) =
  ## Absorb associated data. Must be called before the first data update.
  if not ctx.inAad:
    raise newException(ValueError,
      "associated data must be added before plaintext/ciphertext")
  if ad.len == 0:
    return
  ctx.aadLen += uint64(ad.len)
  ctx.absorb(cast[BytePtr](unsafeAddr ad[0]), ad.len)

proc gctrInto(ctx: var GcmContext, dst, src: BytePtr, n: int) =
  ## XOR `n` bytes with the AES-CTR keystream (counter starts at `ctr`),
  ## keeping a partially consumed keystream block in `kbuf`.
  var dp = dst
  var sp = src
  var left = n
  while left > 0:
    if ctx.kused == 16:
      encryptBlockRaw(ctx.aes, cast[BytePtr](addr ctx.kbuf[0]),
                      cast[BytePtr](addr ctx.ctr[0]))
      inc32(ctx.ctr)
      ctx.kused = 0
    let take = min(gcmBlockSize - ctx.kused, left)
    for i in 0 ..< take:
      dp[i] = sp[i] xor ctx.kbuf[ctx.kused + i]
    ctx.kused += take
    dp = dp + take
    sp = sp + take
    left -= take

proc gcmEncryptUpdate*(ctx: var GcmContext, plaintext: openArray[byte]):
    seq[byte] =
  ## Encrypt the next plaintext chunk and authenticate the ciphertext.
  ctx.flushAad()
  result = newSeqUninit[byte](plaintext.len)
  if plaintext.len > 0:
    var rp = cast[BytePtr](addr result[0])
    let pp = cast[BytePtr](unsafeAddr plaintext[0])
    ctx.gctrInto(rp, pp, plaintext.len)
    ctx.ctLen += uint64(plaintext.len)
    ctx.absorb(rp, plaintext.len)

proc gcmDecryptUpdate*(ctx: var GcmContext, ciphertext: openArray[byte]):
    seq[byte] =
  ## Decrypt the next ciphertext chunk. The returned plaintext must not be
  ## trusted until `finishDec` reports success.
  ctx.flushAad()
  result = newSeqUninit[byte](ciphertext.len)
  if ciphertext.len > 0:
    let cp = cast[BytePtr](unsafeAddr ciphertext[0])
    var rp = cast[BytePtr](addr result[0])
    ctx.ctLen += uint64(ciphertext.len)
    ctx.absorb(cp, ciphertext.len)
    ctx.gctrInto(rp, cp, ciphertext.len)

proc gcmFinishTag(ctx: var GcmContext): array[16, byte] =
  ## Fold the pending tail and lengths, produce E(K,J0) xor GHASH.
  if ctx.bufLen > 0:
    zeroMem(addr ctx.buf[ctx.bufLen], gcmBlockSize - ctx.bufLen)
    ctx.fold(cast[BytePtr](addr ctx.buf[0]))
    ctx.bufLen = 0
  var lens: array[16, byte]
  store64Be(cast[BytePtr](addr lens[0]), ctx.aadLen * 8)
  store64Be(cast[BytePtr](addr lens[8]), ctx.ctLen * 8)
  ctx.fold(cast[BytePtr](addr lens[0]))
  wipe(lens)
  copyMem(addr result[0], addr ctx.acc[0], 16)

proc gcmFinishEnc*(ctx: var GcmContext): array[16, byte] =
  ## Terminate an encryption stream and return the 128-bit tag. Wipes the
  ## context.
  result = ctx.gcmFinishTag()
  var mask: array[16, byte]
  encryptBlockRaw(ctx.aes, cast[BytePtr](addr mask[0]),
                  cast[BytePtr](addr ctx.j0[0]))
  for i in 0 ..< 16:
    result[i] = result[i] xor mask[i]
  wipe(mask)
  wipe(ctx)

proc gcmFinishDec*(ctx: var GcmContext, tag: openArray[byte]): bool =
  ## Verify the tag of a decryption stream (constant time, any length from
  ## 1 to 16 bytes). Wipes the context either way.
  var expect = ctx.gcmFinishTag()
  var mask: array[16, byte]
  encryptBlockRaw(ctx.aes, cast[BytePtr](addr mask[0]),
                  cast[BytePtr](addr ctx.j0[0]))
  for i in 0 ..< 16:
    expect[i] = expect[i] xor mask[i]
  wipe(mask)
  var ok = int(tag.len >= 1 and tag.len <= 16)
  var diff: byte = 0
  for i in 0 ..< tag.len:
    diff = diff or (tag[i] xor expect[i])
  ok = ok and int(diff == 0)
  wipe(expect)
  wipe(ctx)
  result = ok != 0

# ---------------------------------------------------------------------------
# One-shot API.
# ---------------------------------------------------------------------------

proc gcmLock*(key, iv: openArray[byte], plaintext: openArray[byte],
              ad: openArray[byte] = []): (seq[byte], array[16, byte]) =
  ## AES-GCM encryption of a whole message. Returns (ciphertext, tag).
  var ctx: GcmContext
  initGcm(ctx, key, iv)
  gcmAddAad(ctx, ad)
  result[0] = gcmEncryptUpdate(ctx, plaintext)
  result[1] = gcmFinishEnc(ctx)

proc gcmUnlock*(key, iv: openArray[byte], ciphertext: openArray[byte],
                tag: openArray[byte], ad: openArray[byte] = []):
    Option[seq[byte]] =
  ## AES-GCM decryption of a whole message. Returns `some(plaintext)` when
  ## the tag verifies, `none` otherwise (never partial plaintext).
  var ctx: GcmContext
  initGcm(ctx, key, iv)
  gcmAddAad(ctx, ad)
  ctx.flushAad()
  var plain = newSeqUninit[byte](ciphertext.len)
  if ciphertext.len > 0:
    var rp = cast[BytePtr](addr plain[0])
    let cp = cast[BytePtr](unsafeAddr ciphertext[0])
    ctx.ctLen += uint64(ciphertext.len)
    ctx.absorb(cp, ciphertext.len)
    ctx.gctrInto(rp, cp, ciphertext.len)
  if gcmFinishDec(ctx, tag):
    result = some(plain)
  else:
    wipe(plain)
    result = none(seq[byte])

proc gcmLockScalar*(key, iv: openArray[byte], plaintext: openArray[byte],
                    ad: openArray[byte] = []): (seq[byte], array[16, byte]) =
  ## Like `gcmLock` but forced onto the constant-time scalar GHASH kernel
  ## (benchmarking/reference; the result is byte-identical).
  var ctx: GcmContext
  initGcm(ctx, key, iv, forceScalar = true)
  gcmAddAad(ctx, ad)
  result[0] = gcmEncryptUpdate(ctx, plaintext)
  result[1] = gcmFinishEnc(ctx)

proc gcmUnlockScalar*(key, iv: openArray[byte], ciphertext: openArray[byte],
                      tag: openArray[byte], ad: openArray[byte] = []):
    Option[seq[byte]] =
  ## Scalar-kernel variant of `gcmUnlock` (see `gcmLockScalar`).
  var ctx: GcmContext
  initGcm(ctx, key, iv, forceScalar = true)
  gcmAddAad(ctx, ad)
  ctx.flushAad()
  var plain = newSeqUninit[byte](ciphertext.len)
  if ciphertext.len > 0:
    var rp = cast[BytePtr](addr plain[0])
    let cp = cast[BytePtr](unsafeAddr ciphertext[0])
    ctx.ctLen += uint64(ciphertext.len)
    ctx.absorb(cp, ciphertext.len)
    ctx.gctrInto(rp, cp, ciphertext.len)
  if gcmFinishDec(ctx, tag):
    result = some(plain)
  else:
    wipe(plain)
    result = none(seq[byte])

{.pop.}
