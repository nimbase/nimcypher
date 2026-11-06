# PCLMULQDQ-accelerated GHASH via runtime-assembled dynasm JIT (amd64).
#
# Same single-block BearSSL `ghash_pclmul` fold as `ghash_simd.nim`, but
# the machine code is generated at startup/first-use by dynasm instead
# of C-compiler intrinsics: no `nimsimd`, no whole-binary `-mpclmul`
# / `-mssse3` passC flags. The scalar `ghashFoldScalar` in `../gcm`
# stays the reference; differential coverage lives in the test suite.
#
# Buffer lifetime: assemble-once, process-lifetime (never destroyed),
# published with release/acquire so worker threads see it. Lazy so
# non-GCM users pay nothing.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "ghash_jit currently requires amd64.".}

import ../common
import dynasm
import std/locks
import std/atomics

# Register plan (all low XMM, no REX needed):
#   xmm7 bswapIdx (pool, live throughout)   xmm0 yw / scratch
#   xmm1 hw -> t3                            xmm2 hx
#   xmm3 aw                                  xmm4 ax -> t2
#   xmm5 t0                                  xmm6 t1
proc assembleGhashFold(): ExecutableBuffer =
  var a = newAssembler(akX64)
  dynasm a:
    arch x64
    alias accp, rdi, rcx
    alias hp, rsi, rdx
    alias srcp, rdx, r8
    movdqu xmm7, [glob("bswapidx")]
    # yw = bswap(acc)
    movdqu xmm0, [accp]
    pshufb xmm0, xmm7
    # hw = bswap(h); hx = hw xor shufd(hw, 0x0E)
    movdqu xmm1, [hp]
    pshufb xmm1, xmm7
    movdqu xmm2, xmm1
    pshufd xmm3, xmm1, 0x0E
    pxor xmm2, xmm3
    # aw = bswap(src) xor yw; ax = aw xor shufd(aw, 0x0E)
    movdqu xmm3, [srcp]
    pshufb xmm3, xmm7
    pxor xmm3, xmm0
    movdqu xmm4, xmm3
    pshufd xmm0, xmm3, 0x0E
    pxor xmm4, xmm0
    # Karatsuba: t1 = aw*I*hw (0x11), t3 = aw*I*hw (0x00),
    # t2 = ax*hx (0x00) xor t1 xor t3, t0 = shufd(t1)
    movdqu xmm6, xmm3
    pclmulqdq xmm6, xmm1, 0x11
    pclmulqdq xmm1, xmm3, 0x00
    pclmulqdq xmm4, xmm2, 0x00
    pxor xmm4, xmm6
    pxor xmm4, xmm1
    pshufd xmm5, xmm6, 0x0E
    pshufd xmm0, xmm4, 0x0E
    pxor xmm6, xmm0
    pshufd xmm0, xmm1, 0x0E
    pxor xmm4, xmm0
    # sl256 by 1 (t0..t3 = xmm5, xmm6, xmm4, xmm1)
    psllq xmm5, 1
    movdqu xmm0, xmm6
    psrlq xmm0, 63
    por xmm5, xmm0
    psllq xmm6, 1
    movdqu xmm0, xmm4
    psrlq xmm0, 63
    por xmm6, xmm0
    psllq xmm4, 1
    movdqu xmm0, xmm1
    psrlq xmm0, 63
    por xmm4, xmm0
    psllq xmm1, 1
    # reduce; result in xmm5..xmm6 (x0..x1)
    movdqu xmm0, xmm1
    psrlq xmm0, 1
    pxor xmm6, xmm0
    movdqu xmm0, xmm1
    psrlq xmm0, 2
    pxor xmm6, xmm0
    movdqu xmm0, xmm1
    psrlq xmm0, 7
    pxor xmm6, xmm0
    pxor xmm6, xmm1
    movdqu xmm0, xmm1
    psllq xmm0, 63
    pxor xmm4, xmm0
    movdqu xmm0, xmm1
    psllq xmm0, 62
    pxor xmm4, xmm0
    movdqu xmm0, xmm1
    psllq xmm0, 57
    pxor xmm4, xmm0
    pxor xmm5, xmm4
    movdqu xmm0, xmm4
    psrlq xmm0, 1
    pxor xmm5, xmm0
    movdqu xmm0, xmm4
    psrlq xmm0, 2
    pxor xmm5, xmm0
    movdqu xmm0, xmm4
    psrlq xmm0, 7
    pxor xmm5, xmm0
    movdqu xmm0, xmm4
    psllq xmm0, 63
    pxor xmm6, xmm0
    movdqu xmm0, xmm4
    psllq xmm0, 62
    pxor xmm6, xmm0
    movdqu xmm0, xmm4
    psllq xmm0, 57
    pxor xmm6, xmm0
    # yw = bswap(unpacklo(t1, t0)); store
    punpcklqdq xmm6, xmm5
    pshufb xmm6, xmm7
    movdqu [accp], xmm6
    ret()
    global bswapidx
    u8 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  result = a.finalize()

type GhashFoldFn* = proc(acc, h, src: pointer) {.cdecl, gcsafe.}

# Register plan for the 8-block aggregated kernel (needs REX for
# xmm8..xmm15, all supported by the emitter):
#   xmm15 bswapIdx (pool)          xmm0 aw / scratch
#   xmm1 ax -> t2                   xmm2 bw
#   xmm3 bx                         xmm8 shufd tmp
#   xmm4 t_hi -> t1                 xmm5 t_lo -> t3
#   xmm7 t0                         xmm11..14 ACC0..3 (unreduced sum)
proc emitGhashAgg8*(a: var Assembler) =
  ## Fold 8 blocks at [srcp] into [accp] with one reduction (see
  ## assembleGhashAgg8). Caller declares the `accp`/`powp`/`srcp`
  ## aliases; loads the bswap table from `[glob("bswapidx")]` (caller
  ## emits that pool before finalizing). Uses xmm0-8, xmm11-15.
  dynasm a:
    arch x64
    alias accp, rdi, rcx
    alias powp, rsi, rdx
    alias srcp, rdx, r8
    movdqu xmm15, [glob("bswapidx")]
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
  # 9 pairs: acc*P8, X1*P8, X2*P7, .., X8*P1. P_i lives at
  # powp + (i-1)*16. Products accumulate unreduced; shift+reduce run
  # once below (both are XOR-linear, so this equals 8 serial folds).
  for k in 0 ..< 9:
    let powOff = if k == 0: 7 * 16 else: (8 - k) * 16
    if k == 0:
      dynasm a:
        arch x64
        alias accp, rdi, rcx
        movdqu xmm0, [accp]
    else:
      let srcOff = (k - 1) * 16
      dynasm a:
        arch x64
        alias srcp, rdx, r8
        movdqu xmm0, [srcp + srcOff]
    dynasm a:
      arch x64
      alias powp, rsi, rdx
      pshufb xmm0, xmm15
      movdqu xmm2, [powp + powOff]
      pshufb xmm2, xmm15
      movdqu xmm1, xmm0
      pshufd xmm8, xmm0, 0x0E
      pxor xmm1, xmm8
      movdqu xmm3, xmm2
      pshufd xmm8, xmm2, 0x0E
      pxor xmm3, xmm8
      movdqu xmm4, xmm0
      pclmulqdq xmm4, xmm2, 0x11
      movdqu xmm5, xmm0
      pclmulqdq xmm5, xmm2, 0x00
      pclmulqdq xmm1, xmm3, 0x00
      pxor xmm1, xmm4
      pxor xmm1, xmm5
      pshufd xmm7, xmm4, 0x0E
      pshufd xmm8, xmm1, 0x0E
      pxor xmm4, xmm8
      pshufd xmm8, xmm5, 0x0E
      pxor xmm1, xmm8
      pxor xmm11, xmm7
      pxor xmm12, xmm4
      pxor xmm13, xmm1
      pxor xmm14, xmm5
  dynasm a:
    arch x64
    alias accp, rdi, rcx
    # sl256 by 1 over (t0..t3 = xmm11..xmm14)
    psllq xmm11, 1
    movdqu xmm0, xmm12
    psrlq xmm0, 63
    por xmm11, xmm0
    psllq xmm12, 1
    movdqu xmm0, xmm13
    psrlq xmm0, 63
    por xmm12, xmm0
    psllq xmm13, 1
    movdqu xmm0, xmm14
    psrlq xmm0, 63
    por xmm13, xmm0
    psllq xmm14, 1
    # reduce; result in xmm11..xmm12
    movdqu xmm0, xmm14
    psrlq xmm0, 1
    pxor xmm12, xmm0
    movdqu xmm0, xmm14
    psrlq xmm0, 2
    pxor xmm12, xmm0
    movdqu xmm0, xmm14
    psrlq xmm0, 7
    pxor xmm12, xmm0
    pxor xmm12, xmm14
    movdqu xmm0, xmm14
    psllq xmm0, 63
    pxor xmm13, xmm0
    movdqu xmm0, xmm14
    psllq xmm0, 62
    pxor xmm13, xmm0
    movdqu xmm0, xmm14
    psllq xmm0, 57
    pxor xmm13, xmm0
    pxor xmm11, xmm13
    movdqu xmm0, xmm13
    psrlq xmm0, 1
    pxor xmm11, xmm0
    movdqu xmm0, xmm13
    psrlq xmm0, 2
    pxor xmm11, xmm0
    movdqu xmm0, xmm13
    psrlq xmm0, 7
    pxor xmm11, xmm0
    movdqu xmm0, xmm13
    psllq xmm0, 63
    pxor xmm12, xmm0
    movdqu xmm0, xmm13
    psllq xmm0, 62
    pxor xmm12, xmm0
    movdqu xmm0, xmm13
    psllq xmm0, 57
    pxor xmm12, xmm0
    punpcklqdq xmm12, xmm11
    pshufb xmm12, xmm15
    movdqu [accp], xmm12

proc assembleGhashAgg8(): ExecutableBuffer =
  var a = newAssembler(akX64)
  emitGhashAgg8(a)
  dynasm a:
    arch x64
    ret()
    global bswapidx
    u8 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  result = a.finalize()

var gGhashLock: Lock
initLock(gGhashLock) # module init runs single-threaded before main
var gGhashBuf: ExecutableBuffer
var gGhashReady: Atomic[bool]

proc ensureGhashJit() =
  ## Double-checked assemble-once. Fast path is one relaxed atomic
  ## load; the buffer write is sequenced before the release store.
  if gGhashReady.load(moAcquire):
    return
  withLock(gGhashLock):
    if gGhashReady.load(moRelaxed):
      return
    gGhashBuf = assembleGhashFold()
    gGhashReady.store(true, moRelease)

proc ghashFoldJitAvailable*(): bool =
  ## True once the kernel assembled (false only if exec memory is
  ## unavailable, e.g. W^X-hardened targets — caller falls back).
  try:
    ensureGhashJit()
  except CatchableError:
    return false
  true

proc ghashFoldJit*(acc: var array[16, byte], h: array[16, byte],
                   src: BytePtr) =
  ## acc = (acc xor block) * H mod(x^128 + x^7 + x^2 + x + 1).
  ## Raises on assembly failure; check ghashFoldJitAvailable first or
  ## let the gcm dispatch wrapper fall back.
  ensureGhashJit()
  let f = cast[GhashFoldFn](gGhashBuf.ptrAt(AssemblyOffset(0)))
  f(addr acc[0], unsafeAddr h[0], cast[pointer](src))

type GhashAgg8Fn* = proc(acc, pow, src: pointer) {.cdecl, gcsafe.}

var gGhashAggBuf: ExecutableBuffer
var gGhashAggReady: Atomic[bool]

proc ensureGhashAggJit() =
  if gGhashAggReady.load(moAcquire):
    return
  withLock(gGhashLock):
    if gGhashAggReady.load(moRelaxed):
      return
    gGhashAggBuf = assembleGhashAgg8()
    gGhashAggReady.store(true, moRelease)

proc ghashAgg8JitAvailable*(): bool =
  ## True once the 8-block kernel assembled (false only if exec memory
  ## is unavailable — caller falls back to serial folds).
  try:
    ensureGhashAggJit()
  except CatchableError:
    return false
  true

proc ghashAgg8Jit*(acc: var array[16, byte], hpow: BytePtr, src: BytePtr) =
  ## Fold 8 blocks at `src` (128 bytes) into `acc` in one shot:
  ## acc = acc*H^8 xor X1*H^8 xor X2*H^7 .. xor X8*H, with a single
  ## reduction. `hpow` points at 8 consecutive powers P1..P8 (16 bytes
  ## each, same block format as the H key). Raises on assembly failure;
  ## check ghashAgg8JitAvailable first.
  ensureGhashAggJit()
  let f = cast[GhashAgg8Fn](gGhashAggBuf.ptrAt(AssemblyOffset(0)))
  f(addr acc[0], cast[pointer](hpow), cast[pointer](src))
