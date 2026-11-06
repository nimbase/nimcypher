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
