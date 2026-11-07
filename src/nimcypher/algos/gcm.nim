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

when defined(features.nimcypher.nimdynasm) and
    (defined(amd64) or defined(arm64)):
  import ./internal/aes_jit

when defined(features.nimcypher.nimdynasm) and defined(amd64):
  import ./internal/ghash_jit
  import ./internal/gcm_jit

{.push checks: off.}

const gcmBlockSize = 16

const gcmGhashPowSlots = 16
  ## Aggregated-kernel power table size: 8 byte-swapped H^1..H^8 then
  ## their Karatsuba folds. Kept local so non-JIT builds compile without
  ## importing `ghash_jit`; the JIT build asserts the two agree.

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

when defined(features.nimcypher.nimdynasm) and defined(amd64):
  proc ghashFold*(acc: var array[16, byte], h: array[16, byte],
                  src: BytePtr) {.inline.} =
    ## JIT fast path, assembled once by dynasm; falls back when exec
    ## memory is unavailable (or to the nimsimd kernel when both
    ## features are on), then to scalar.
    if ghashFoldJitAvailable():
      ghashFoldJit(acc, h, src)
    else:
      when defined(features.nimcypher.nimsimd):
        ghashFoldClmul(acc, h, src)
      else:
        ghashFoldScalar(acc, h, src)
elif defined(features.nimcypher.nimsimd) and defined(amd64):
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
    # Contiguous fused-kernel block {ctr, acc, pow}: the JIT crypt
    # kernel takes one pointer to ctr and advances/folds in place.
    ctr: array[16, byte]    # GCTR counter block (starts at inc32(J0))
    acc*: array[16, byte]   # GHASH accumulator (big-endian block)
    hPow: array[gcmGhashPowSlots, array[16, byte]] # bswapped H^i + folds
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

proc foldBlocks(ctx: var GcmContext, p: BytePtr, nb: int) =
  ## Fold `nb` whole blocks; 8-at-a-time through the aggregated JIT
  ## kernel when available, serial dispatch for the tail (or everywhere
  ## when forced scalar / exec memory is unavailable).
  var pp = p
  var left = nb
  when defined(features.nimcypher.nimdynasm) and defined(amd64):
    if not ctx.forceScalar and left >= 8:
      if ghashAgg8JitAvailable():
        while left >= 8:
          ghashAgg8Jit(ctx.acc, cast[BytePtr](addr ctx.hPow[0]), pp)
          pp = pp + 128
          left -= 8
  while left > 0:
    ctx.fold(pp)
    pp = pp + gcmBlockSize
    left -= 1

const gcmBatchBlocks = 32 # fused-loop chunk, multiple of the 8-block JIT batch

proc fuseEncryptBlocks(ctx: var GcmContext, dst, src: BytePtr,
                       nbBlocks: int) =
  ## Whole-block fused CTR-encrypt + GHASH-fold for the clean state
  ## (`bufLen == 0`, `kused == 16`). Octets go through the CTR kernel
  ## (in-kernel counter gen + xor); a sub-octet remainder uses the
  ## buffered path. The chunk is folded while still hot.
  var dp = dst
  var sp = src
  var left = nbBlocks
  var cbs: array[gcmBatchBlocks * gcmBlockSize, byte]
  var ks: array[gcmBatchBlocks * gcmBlockSize, byte]
  while left > 0:
    let nb = min(left, gcmBatchBlocks)
    var produced = 0
    when defined(features.nimcypher.nimdynasm) and
      (defined(amd64) or defined(arm64)):
      if aesJitAvailable():
        while produced + aesJitBatch <= nb:
          ctrCrypt8Jit(ctx.aes.rounds, addr ctx.aes.nrk[0],
                       dp + (produced shl 4), sp + (produced shl 4),
                       cast[BytePtr](addr ctx.ctr[0]))
          produced += aesJitBatch
    if produced < nb:
      let rn = nb - produced
      let ro = produced shl 4
      for b in 0 ..< rn:
        copyMem(addr cbs[b * gcmBlockSize], addr ctx.ctr[0], gcmBlockSize)
        inc32(ctx.ctr)
      encryptBlocks(ctx.aes, cast[BytePtr](addr ks[0]),
                    cast[BytePtr](addr cbs[0]), rn)
      let rfull = rn shl 4
      for i in 0 ..< rfull:
        dp[ro + i] = sp[ro + i] xor ks[i]
    ctx.foldBlocks(dp, nb)
    ctx.ctLen += uint64(nb shl 4)
    dp = dp + (nb shl 4)
    sp = sp + (nb shl 4)
    left -= nb
  wipe(ks)

proc fuseDecryptBlocks(ctx: var GcmContext, dst, src: BytePtr,
                       nbBlocks: int) =
  ## Whole-block fused GHASH-fold + CTR-decrypt for the clean state.
  ## The fold reads the ciphertext before it is xored into plaintext.
  var dp = dst
  var sp = src
  var left = nbBlocks
  var cbs: array[gcmBatchBlocks * gcmBlockSize, byte]
  var ks: array[gcmBatchBlocks * gcmBlockSize, byte]
  while left > 0:
    let nb = min(left, gcmBatchBlocks)
    ctx.foldBlocks(sp, nb)
    var produced = 0
    when defined(features.nimcypher.nimdynasm) and
      (defined(amd64) or defined(arm64)):
      if aesJitAvailable():
        while produced + aesJitBatch <= nb:
          ctrCrypt8Jit(ctx.aes.rounds, addr ctx.aes.nrk[0],
                       dp + (produced shl 4), sp + (produced shl 4),
                       cast[BytePtr](addr ctx.ctr[0]))
          produced += aesJitBatch
    if produced < nb:
      let rn = nb - produced
      let ro = produced shl 4
      for b in 0 ..< rn:
        copyMem(addr cbs[b * gcmBlockSize], addr ctx.ctr[0], gcmBlockSize)
        inc32(ctx.ctr)
      encryptBlocks(ctx.aes, cast[BytePtr](addr ks[0]),
                    cast[BytePtr](addr cbs[0]), rn)
      let rfull = rn shl 4
      for i in 0 ..< rfull:
        dp[ro + i] = sp[ro + i] xor ks[i]
    ctx.ctLen += uint64(nb shl 4)
    dp = dp + (nb shl 4)
    sp = sp + (nb shl 4)
    left -= nb
  wipe(ks)

when defined(features.nimcypher.nimdynasm) and defined(amd64):
  proc fuseEncryptBlocksFused(ctx: var GcmContext, dst, src: BytePtr,
                              nbBlocks: int) =
    ## Whole-block path through the fused crypt kernels: one call per
    ## 32 blocks (wide) then per 8 blocks (narrow) does counter-gen +
    ## AES + xor + GHASH. A sub-octet tail uses the buffered path.
    ## Clean state only (caller guarantees `bufLen == 0`, `kused == 16`).
    var dp = dst
    var sp = src
    var left = nbBlocks
    if left >= gcmWideStages * aesJitBatch:
      # Resolve the kernel once; the per-chunk dispatch cost dominated
      # the remaining record overhead (32 calls per 16 KiB).
      let f = gcmCrypt32Fn(ctx.aes.rounds, false)
      let nrk = addr ctx.aes.nrk[0]
      let blk = cast[BytePtr](addr ctx.ctr[0])
      while left >= gcmWideStages * aesJitBatch:
        f(nrk, cast[pointer](sp), cast[pointer](dp), cast[pointer](blk))
        dp = dp + 512
        sp = sp + 512
        left -= gcmWideStages * aesJitBatch
        ctx.ctLen += uint64(gcmWideStages * aesJitBatch * 16)
    while left >= aesJitBatch:
      gcmCrypt8Jit(ctx.aes.rounds, addr ctx.aes.nrk[0], dp, sp,
                   cast[BytePtr](addr ctx.ctr[0]))
      dp = dp + 128
      sp = sp + 128
      left -= aesJitBatch
      ctx.ctLen += 128
    if left > 0:
      ctx.fuseEncryptBlocks(dp, sp, left)

  proc fuseDecryptBlocksFused(ctx: var GcmContext, dst, src: BytePtr,
                              nbBlocks: int) =
    ## Whole-block fused decrypt (same kernels; CTR mode decrypts with
    ## the same keystream). Sub-octet tail uses the buffered path.
    var dp = dst
    var sp = src
    var left = nbBlocks
    if left >= gcmWideStages * aesJitBatch:
      let f = gcmCrypt32Fn(ctx.aes.rounds, true)
      let nrk = addr ctx.aes.nrk[0]
      let blk = cast[BytePtr](addr ctx.ctr[0])
      while left >= gcmWideStages * aesJitBatch:
        f(nrk, cast[pointer](dp), cast[pointer](sp), cast[pointer](blk))
        dp = dp + 512
        sp = sp + 512
        left -= gcmWideStages * aesJitBatch
        ctx.ctLen += uint64(gcmWideStages * aesJitBatch * 16)
    while left >= aesJitBatch:
      gcmCrypt8Jit(ctx.aes.rounds, addr ctx.aes.nrk[0], dp, sp,
                   cast[BytePtr](addr ctx.ctr[0]), decrypt = true)
      dp = dp + 128
      sp = sp + 128
      left -= aesJitBatch
      ctx.ctLen += 128
    if left > 0:
      ctx.fuseDecryptBlocks(dp, sp, left)

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
      let nb = left shr 4
      if nb > 0:
        ctx.foldBlocks(pp, nb)
        pp = pp + (nb shl 4)
        left -= nb shl 4
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
  when defined(features.nimcypher.nimdynasm) and defined(amd64):
    static: doAssert gcmGhashPowSlots == ghashPowSlots
    if not forceScalar:
      # Powers P1..P8 for the aggregated kernel: P[i+1] = P[i] * H,
      # then the kernel's byte-swapped + folded forms (once per key).
      var raw: array[8, array[16, byte]]
      raw[0] = ctx.hBlock
      var z: array[16, byte]
      for i in 1 ..< 8:
        zeroMem(addr z[0], 16)
        ghashFold(z, ctx.hBlock, cast[BytePtr](addr raw[i - 1][0]))
        raw[i] = z
      wipe(z)
      buildGhashPowers(ctx.hPow, raw)
      wipe(raw)
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

# ---------------------------------------------------------------------------
# Key sessions: cache the per-key schedule + GHASH powers across records.
# initGcm above re-expands the key and recomputes H^1..H^8 on every call
# (~1.2 us); a session pays that once per key and each record only
# copies the schedule in (~50 ns) plus its own J0/counter setup.
# ---------------------------------------------------------------------------

type
  GcmSession* = object
    aes: AesContext
    hBlock: array[16, byte]
    hPow: array[gcmGhashPowSlots, array[16, byte]]

proc initGcmSession*(key: openArray[byte]): GcmSession =
  ## Expand the AES schedule, H = E_K(0^128) and H^1..H^8 once.
  ## Raises ValueError on an invalid key length.
  initAes(result.aes, key)
  var zero: array[16, byte]
  encryptBlockRaw(result.aes, cast[BytePtr](addr result.hBlock[0]),
                  cast[BytePtr](addr zero[0]))
  wipe(zero)
  when defined(features.nimcypher.nimdynasm) and defined(amd64):
    var raw: array[8, array[16, byte]]
    raw[0] = result.hBlock
    var z: array[16, byte]
    for i in 1 ..< 8:
      zeroMem(addr z[0], 16)
      ghashFold(z, result.hBlock, cast[BytePtr](addr raw[i - 1][0]))
      raw[i] = z
    wipe(z)
    buildGhashPowers(result.hPow, raw)
    wipe(raw)

proc initGcmWithSession*(ctx: var GcmContext, s: GcmSession,
                         iv: openArray[byte], forceScalar = false) =
  ## Per-record init from a cached session: copies the schedule (no key
  ## expansion, no power precompute), then J0/counter setup as usual.
  if iv.len == 0:
    raise newException(ValueError, "GCM IV must not be empty")
  ctx.aes = s.aes
  ctx.hBlock = s.hBlock
  ctx.hPow = s.hPow
  zeroMem(addr ctx.acc[0], 16)
  ctx.bufLen = 0
  ctx.kused = 16
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
  inc32(ctx.ctr)

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
  ## Fast path batches full blocks through `encryptBlocks` (JIT/SIMD 8-block
  ## kernels when enabled); the counter uses GCM `inc32` semantics, so this
  ## cannot reuse the generic 128-bit `ctrXorInto`.
  var dp = dst
  var sp = src
  var left = n
  # Drain any pending keystream from a previous partial call.
  if ctx.kused != 16:
    let take = min(gcmBlockSize - ctx.kused, left)
    for i in 0 ..< take:
      dp[i] = sp[i] xor ctx.kbuf[ctx.kused + i]
    ctx.kused += take
    dp = dp + take
    sp = sp + take
    left -= take
    if left == 0:
      return
  # Bulk: generate counter blocks, encrypt as a batch, xor.
  const batchBlocks = 32 # multiple of the 8-block JIT batch
  var cbs: array[batchBlocks * gcmBlockSize, byte]
  var ks: array[batchBlocks * gcmBlockSize, byte]
  while left >= gcmBlockSize:
    let nb = min(left shr 4, batchBlocks)
    for b in 0 ..< nb:
      copyMem(addr cbs[b * gcmBlockSize], addr ctx.ctr[0], gcmBlockSize)
      inc32(ctx.ctr)
    encryptBlocks(ctx.aes, cast[BytePtr](addr ks[0]),
                  cast[BytePtr](addr cbs[0]), nb)
    let full = nb shl 4
    for i in 0 ..< full:
      dp[i] = sp[i] xor ks[i]
    dp = dp + full
    sp = sp + full
    left -= full
  # Partial tail: one fresh keystream block held in kbuf.
  if left > 0:
    encryptBlocks(ctx.aes, cast[BytePtr](addr ctx.kbuf[0]),
                  cast[BytePtr](addr ctx.ctr[0]), 1)
    inc32(ctx.ctr)
    ctx.kused = 0
    for i in 0 ..< left:
      dp[i] = sp[i] xor ctx.kbuf[i]
    ctx.kused = left
  else:
    ctx.kused = 16
  wipe(ks)

proc gcmEncryptUpdate*(ctx: var GcmContext, plaintext: openArray[byte]):
    seq[byte] =
  ## Encrypt the next plaintext chunk and authenticate the ciphertext.
  ctx.flushAad()
  result = newSeqUninit[byte](plaintext.len)
  if plaintext.len > 0:
    var rp = cast[BytePtr](addr result[0])
    let pp = cast[BytePtr](unsafeAddr plaintext[0])
    if ctx.bufLen == 0 and ctx.kused == 16:
      let nbFull = plaintext.len shr 4
      if nbFull > 0:
        when defined(features.nimcypher.nimdynasm) and defined(amd64):
          if not ctx.forceScalar and gcmCrypt8JitAvailable():
            ctx.fuseEncryptBlocksFused(rp, pp, nbFull)
          else:
            ctx.fuseEncryptBlocks(rp, pp, nbFull)
        else:
          ctx.fuseEncryptBlocks(rp, pp, nbFull)
      let tail = plaintext.len and 15
      if tail > 0:
        let off = nbFull shl 4
        ctx.gctrInto(rp + off, pp + off, tail)
        ctx.absorb(rp + off, tail)
        ctx.ctLen += uint64(tail)
    else:
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
    if ctx.bufLen == 0 and ctx.kused == 16:
      let nbFull = ciphertext.len shr 4
      if nbFull > 0:
        when defined(features.nimcypher.nimdynasm) and defined(amd64):
          if not ctx.forceScalar and gcmCrypt8JitAvailable():
            ctx.fuseDecryptBlocksFused(rp, cp, nbFull)
          else:
            ctx.fuseDecryptBlocks(rp, cp, nbFull)
        else:
          ctx.fuseDecryptBlocks(rp, cp, nbFull)
      let tail = ciphertext.len and 15
      if tail > 0:
        let off = nbFull shl 4
        ctx.absorb(cp + off, tail)
        ctx.ctLen += uint64(tail)
        ctx.gctrInto(rp + off, cp + off, tail)
    else:
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

proc gcmLockWithSession*(s: GcmSession, iv: openArray[byte],
                         plaintext: openArray[byte],
                         ad: openArray[byte] = []): (seq[byte],
    array[16, byte]) =
  ## Like `gcmLock` but reuses a cached session: no key expansion, no
  ## power precompute, just the per-record J0/counter setup.
  var ctx: GcmContext
  initGcmWithSession(ctx, s, iv)
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
  let plain = gcmDecryptUpdate(ctx, ciphertext)
  if gcmFinishDec(ctx, tag):
    result = some(plain)
  else:
    var m = plain
    wipe(m)
    result = none(seq[byte])

proc gcmUnlockWithSession*(s: GcmSession, iv: openArray[byte],
                           ciphertext: openArray[byte],
                           tag: openArray[byte], ad: openArray[byte] = []):
    Option[seq[byte]] =
  ## Like `gcmUnlock` but reuses a cached session (see
  ## `gcmLockWithSession`).
  var ctx: GcmContext
  initGcmWithSession(ctx, s, iv)
  gcmAddAad(ctx, ad)
  let plain = gcmDecryptUpdate(ctx, ciphertext)
  if gcmFinishDec(ctx, tag):
    result = some(plain)
  else:
    var m = plain
    wipe(m)
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
  let plain = gcmDecryptUpdate(ctx, ciphertext)
  if gcmFinishDec(ctx, tag):
    result = some(plain)
  else:
    var m = plain
    wipe(m)
    result = none(seq[byte])

{.pop.}
