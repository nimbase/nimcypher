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

proc assembleChachaRounds(): ExecutableBuffer =
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

var gChachaLock: Lock
initLock(gChachaLock) # module init runs single-threaded at startup
var gChachaBuf: ExecutableBuffer
var gChachaReady: Atomic[bool]

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
