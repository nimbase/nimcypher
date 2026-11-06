# ChaCha20 rounds via runtime-assembled dynasm JIT (amd64 only).
#
# Same contract as `simdRounds` (one block, four 128-bit lanes holding
# the four column groups): 10 iterations of double-round
# (vector quarter-round, diagonal lane shuffle, vector quarter-round,
# shuffle back). Uses only SSE2 integer ops (paddd/pxor/pshufd with
# dword shifts), so every amd64 target runs it — no AVX2 gate needed.
# This is the kernel behind `chacha20Rounds`, hence behind IETF bulk,
# HChaCha20 and the DJB odd/partial blocks. The AVX2 two-block DJB
# kernel (`simdRounds2` shape) is a separate follow-up.
#
# Assemble-once, process-lifetime cache behind the usual global
# lock + atomic publish. No constant pool (shuffles/rotations are
# immediates); kernel starts at offset 0 and ends with ret.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "chacha_jit currently requires amd64.".}

import ../common
import dynasm
import std/locks
import std/atomics
import ./cpu_jit
export cpu_jit.cpuHasAvx2

var gChachaLock: Lock
initLock(gChachaLock) # module init runs single-threaded at startup
var gChachaBuf: ExecutableBuffer
var gChachaReady: Atomic[bool]
var gChachaBuf2: ExecutableBuffer
var gChachaReady2: Atomic[bool]

proc assembleChachaRounds(): ExecutableBuffer =
  ## 4-lane SSE2 kernel (see module header). Legacy in-place shifts cost
  ## one movdqu per rotate; bulk 64-bit multiples should use the 8-lane
  ## AVX2 kernel below instead.
  var a = newAssembler(akX64)
  # Load state columns: a=xmm0, b=xmm1, c=xmm2, d=xmm3.
  dynasm a:
    arch x64
    alias inp, rsi, rdx
    movdqu xmm0, [inp]
    movdqu xmm1, [inp + 16]
    movdqu xmm2, [inp + 32]
    movdqu xmm3, [inp + 48]
  # One double-round: QR, diagonal shuffle, QR, shuffle back. The two
  # QR bodies are identical; shuffles pick column vs diagonal groups.
  for _ in 0 ..< 10:
    dynasm a:
      arch x64
      # a += b; d = rotl(d xor a, 16)
      paddd xmm0, xmm1
      pxor xmm3, xmm0
      movdqu xmm4, xmm3
      pslld xmm4, 16
      psrld xmm3, 16
      por xmm3, xmm4
      # c += d; b = rotl(b xor c, 12)
      paddd xmm2, xmm3
      pxor xmm1, xmm2
      movdqu xmm4, xmm1
      pslld xmm4, 12
      psrld xmm1, 20
      por xmm1, xmm4
      # a += b; d = rotl(d xor a, 8)
      paddd xmm0, xmm1
      pxor xmm3, xmm0
      movdqu xmm4, xmm3
      pslld xmm4, 8
      psrld xmm3, 24
      por xmm3, xmm4
      # c += d; b = rotl(b xor c, 7)
      paddd xmm2, xmm3
      pxor xmm1, xmm2
      movdqu xmm4, xmm1
      pslld xmm4, 7
      psrld xmm1, 25
      por xmm1, xmm4
      # diagonal shuffle: b rot1, c rot2, d rot3
      pshufd xmm1, xmm1, 0x39
      pshufd xmm2, xmm2, 0x4E
      pshufd xmm3, xmm3, 0x93
      # a += b; d = rotl(d xor a, 16)
      paddd xmm0, xmm1
      pxor xmm3, xmm0
      movdqu xmm4, xmm3
      pslld xmm4, 16
      psrld xmm3, 16
      por xmm3, xmm4
      # c += d; b = rotl(b xor c, 12)
      paddd xmm2, xmm3
      pxor xmm1, xmm2
      movdqu xmm4, xmm1
      pslld xmm4, 12
      psrld xmm1, 20
      por xmm1, xmm4
      # a += b; d = rotl(d xor a, 8)
      paddd xmm0, xmm1
      pxor xmm3, xmm0
      movdqu xmm4, xmm3
      pslld xmm4, 8
      psrld xmm3, 24
      por xmm3, xmm4
      # c += d; b = rotl(b xor c, 7)
      paddd xmm2, xmm3
      pxor xmm1, xmm2
      movdqu xmm4, xmm1
      pslld xmm4, 7
      psrld xmm1, 25
      por xmm1, xmm4
      # shuffle back: b rot3, c rot2, d rot1
      pshufd xmm1, xmm1, 0x93
      pshufd xmm2, xmm2, 0x4E
      pshufd xmm3, xmm3, 0x39
  dynasm a:
    arch x64
    alias outp, rdi, rcx
    movdqu [outp], xmm0
    movdqu [outp + 16], xmm1
    movdqu [outp + 32], xmm2
    movdqu [outp + 48], xmm3
    ret()
  result = a.finalize()

type ChachaJitFn* = proc(outp, inp: pointer) {.cdecl, gcsafe.}

proc assembleChachaRounds2(): ExecutableBuffer =
  ## 8-lane AVX2 kernel: two blocks in parallel, one per 128-bit lane.
  ## Same vector quarter-round structure as the 4-lane kernel, but VEX
  ## 3-operand shifts make rotates copy-free. Diagonal lane shuffles go
  ## through VEX vpshufb with index vectors (ymm5..7, loaded once from
  ## the pool — VEX vpshufd and vpshufb-mem both misexecute on at least
  ## one host class, while the reg form is fine). Input/output layout
  ## matches `simdRounds2`: word w of block 0 at
  ## [(w shr 2) shl 3 + (w and 3)], word w of block 1 four words later.
  ## Uses the OSXSAVE+XCR0 gate (`chachaAvx2Available`), not just CPUID.
  var a = newAssembler(akX64)
  dynasm a:
    arch x64
    alias inp, rsi, rdx
    vmovdqu ymm0, [inp]
    vmovdqu ymm1, [inp + 32]
    vmovdqu ymm2, [inp + 64]
    vmovdqu ymm3, [inp + 96]
    vmovdqu ymm5, [glob("shuf39")]
    vmovdqu ymm6, [glob("shuf4e")]
    vmovdqu ymm7, [glob("shuf93")]
  for _ in 0 ..< 10:
    dynasm a:
      arch x64
      # column round
      vpaddd ymm0, ymm0, ymm1
      vpxor ymm3, ymm3, ymm0
      vpslld ymm4, ymm3, 16
      vpsrld ymm3, ymm3, 16
      vpor ymm3, ymm3, ymm4
      vpaddd ymm2, ymm2, ymm3
      vpxor ymm1, ymm1, ymm2
      vpslld ymm4, ymm1, 12
      vpsrld ymm1, ymm1, 20
      vpor ymm1, ymm1, ymm4
      vpaddd ymm0, ymm0, ymm1
      vpxor ymm3, ymm3, ymm0
      vpslld ymm4, ymm3, 8
      vpsrld ymm3, ymm3, 24
      vpor ymm3, ymm3, ymm4
      vpaddd ymm2, ymm2, ymm3
      vpxor ymm1, ymm1, ymm2
      vpslld ymm4, ymm1, 7
      vpsrld ymm1, ymm1, 25
      vpor ymm1, ymm1, ymm4
      vpshufb ymm1, ymm1, ymm5
      vpshufb ymm2, ymm2, ymm6
      vpshufb ymm3, ymm3, ymm7
      # diagonal round
      vpaddd ymm0, ymm0, ymm1
      vpxor ymm3, ymm3, ymm0
      vpslld ymm4, ymm3, 16
      vpsrld ymm3, ymm3, 16
      vpor ymm3, ymm3, ymm4
      vpaddd ymm2, ymm2, ymm3
      vpxor ymm1, ymm1, ymm2
      vpslld ymm4, ymm1, 12
      vpsrld ymm1, ymm1, 20
      vpor ymm1, ymm1, ymm4
      vpaddd ymm0, ymm0, ymm1
      vpxor ymm3, ymm3, ymm0
      vpslld ymm4, ymm3, 8
      vpsrld ymm3, ymm3, 24
      vpor ymm3, ymm3, ymm4
      vpaddd ymm2, ymm2, ymm3
      vpxor ymm1, ymm1, ymm2
      vpslld ymm4, ymm1, 7
      vpsrld ymm1, ymm1, 25
      vpor ymm1, ymm1, ymm4
      vpshufb ymm1, ymm1, ymm7
      vpshufb ymm2, ymm2, ymm6
      vpshufb ymm3, ymm3, ymm5
  dynasm a:
    arch x64
    alias outp, rdi, rcx
    vmovdqu [outp], ymm0
    vmovdqu [outp + 32], ymm1
    vmovdqu [outp + 64], ymm2
    vmovdqu [outp + 96], ymm3
    vzeroupper()
    ret()
    # Byte shuffle indices implementing vpshufd 0x39/0x4E/0x93 per
    # 128-bit lane (both lanes identical).
    global shuf39
    u8 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3,
      4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3
    global shuf4e
    u8 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
      8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7
    global shuf93
    u8 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
      12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
  result = a.finalize()

proc ensureChachaJit2() =
  if gChachaReady2.load(moAcquire):
    return
  withLock(gChachaLock):
    if gChachaReady2.load(moRelaxed):
      return
    gChachaBuf2 = assembleChachaRounds2()
    gChachaReady2.store(true, moRelease)

proc chacha20Rounds2Jit*(outp: var array[32, uint32],
                         inp: array[32, uint32]) =
  ## Apply 20 rounds to two blocks at once (same contract as
  ## `simdRounds2`). Requires AVX2 + OS YMM support; check
  ## cpuHasAvx2() first.
  ensureChachaJit2()
  let f = cast[ChachaJitFn](gChachaBuf2.ptrAt(AssemblyOffset(0)))
  f(addr outp[0], unsafeAddr inp[0])

proc ensureChachaJit() =
  if gChachaReady.load(moAcquire):
    return
  withLock(gChachaLock):
    if gChachaReady.load(moRelaxed):
      return
    gChachaBuf = assembleChachaRounds()
    gChachaReady.store(true, moRelease)

proc chachaJitAvailable*(): bool =
  try:
    ensureChachaJit()
  except CatchableError:
    return false
  true

proc chacha20RoundsJit*(outp: var array[16, uint32],
                        inp: array[16, uint32]) =
  ## Apply 20 rounds of ChaCha20 to one block (same contract as
  ## `simdRounds` / `chacha20RoundsScalar`).
  ensureChachaJit()
  let f = cast[ChachaJitFn](gChachaBuf.ptrAt(AssemblyOffset(0)))
  f(addr outp[0], unsafeAddr inp[0])
