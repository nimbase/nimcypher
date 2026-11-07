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

proc emitChachaRounds2(a: var Assembler) =
  ## Ten double-rounds over the 8-lane state in ymm0..3 (shuffle tables
  ## in ymm5..7). Shared by the rounds-only and the fused crypt kernel.
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
  emitChachaRounds2(a)
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

proc assembleChachaCrypt2(): ExecutableBuffer =
  ## Fused 8-lane crypt: rounds over the interleaved input at [inp],
  ## pool stored to [poolp], then (pool + input) xor plaintext stored to
  ## [dstp], all in one call. The row-group epilogue uses only legacy
  ## SSE 16-byte forms after vzeroupper (no VEX on any host class): row g of block k lives contiguously at pool/din
  ## byte offset 32*g + 16*k and maps to ct/pt bytes 16*g (+ 64 for
  ## block 1), so each half is load/add/load/xor/store with no gathers.
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
  emitChachaRounds2(a)
  dynasm a:
    arch x64
    alias poolp, rdi, rcx
    vmovdqu [poolp], ymm0
    vmovdqu [poolp + 32], ymm1
    vmovdqu [poolp + 64], ymm2
    vmovdqu [poolp + 96], ymm3
    vzeroupper()
  for g in 0 ..< 4:
    let o = g * 32
    let o16 = o + 16
    let p = g * 16
    let p64 = 64 + p
    dynasm a:
      arch x64
      alias inp, rsi, rdx
      alias poolp, rdi, rcx
      alias dstp, rdx, r8
      alias srcp, rcx, r9
      movdqu xmm0, [poolp + o]
      movdqu xmm1, [inp + o]
      paddd xmm0, xmm1
      movdqu xmm1, [srcp + p]
      pxor xmm0, xmm1
      movdqu [dstp + p], xmm0
      movdqu xmm0, [poolp + o16]
      movdqu xmm1, [inp + o16]
      paddd xmm0, xmm1
      movdqu xmm1, [srcp + p64]
      pxor xmm0, xmm1
      movdqu [dstp + p64], xmm0
  dynasm a:
    arch x64
    ret()
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

var gChachaCryptBuf: ExecutableBuffer
var gChachaCryptReady: Atomic[bool]

proc ensureChachaCryptJit() =
  if gChachaCryptReady.load(moAcquire):
    return
  withLock(gChachaLock):
    if gChachaCryptReady.load(moRelaxed):
      return
    gChachaCryptBuf = assembleChachaCrypt2()
    gChachaCryptReady.store(true, moRelease)

type ChachaCryptFn* = proc(poolp, inp, dstp, srcp: pointer) {.cdecl, gcsafe.}

proc chacha20Crypt2Jit*(dst, src: BytePtr, pool: var array[32, uint32],
                        din: array[32, uint32]) =
  ## Rounds + add + xor + store for a block pair (same layout contract
  ## as `chacha20Rounds2Jit`; plaintext at `src`, ciphertext at `dst`).
  ## Requires AVX2 + OS YMM support; check cpuHasAvx2() first.
  ensureChachaCryptJit()
  let f = cast[ChachaCryptFn](gChachaCryptBuf.ptrAt(AssemblyOffset(0)))
  f(addr pool[0], unsafeAddr din[0], cast[pointer](dst),
    cast[pointer](src))

proc emitChachaRounds4(a: var Assembler) =
  ## Ten double-rounds over two 2-block groups: A in ymm0..3 (temp ymm4),
  ## B in ymm8..11 (temp ymm12), shuffle tables shared in ymm5..7.
  ## Groups run back-to-back per double-round; the chains are independent
  ## so the out-of-order window overlaps them (~2x rounds ILP vs the
  ## 2-block kernel). Body is a mechanical rename of `emitChachaRounds2`
  ## (same verified VEX forms, no extracts/inserts).
  for _ in 0 ..< 10:
    dynasm a:
      arch x64
      # group A column round
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
      # group B column round
      vpaddd ymm8, ymm8, ymm9
      vpxor ymm11, ymm11, ymm8
      vpslld ymm12, ymm11, 16
      vpsrld ymm11, ymm11, 16
      vpor ymm11, ymm11, ymm12
      vpaddd ymm10, ymm10, ymm11
      vpxor ymm9, ymm9, ymm10
      vpslld ymm12, ymm9, 12
      vpsrld ymm9, ymm9, 20
      vpor ymm9, ymm9, ymm12
      vpaddd ymm8, ymm8, ymm9
      vpxor ymm11, ymm11, ymm8
      vpslld ymm12, ymm11, 8
      vpsrld ymm11, ymm11, 24
      vpor ymm11, ymm11, ymm12
      vpaddd ymm10, ymm10, ymm11
      vpxor ymm9, ymm9, ymm10
      vpslld ymm12, ymm9, 7
      vpsrld ymm9, ymm9, 25
      vpor ymm9, ymm9, ymm12
      vpshufb ymm9, ymm9, ymm5
      vpshufb ymm10, ymm10, ymm6
      vpshufb ymm11, ymm11, ymm7
      # group A diagonal round
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
      # group B diagonal round
      vpaddd ymm8, ymm8, ymm9
      vpxor ymm11, ymm11, ymm8
      vpslld ymm12, ymm11, 16
      vpsrld ymm11, ymm11, 16
      vpor ymm11, ymm11, ymm12
      vpaddd ymm10, ymm10, ymm11
      vpxor ymm9, ymm9, ymm10
      vpslld ymm12, ymm9, 12
      vpsrld ymm9, ymm9, 20
      vpor ymm9, ymm9, ymm12
      vpaddd ymm8, ymm8, ymm9
      vpxor ymm11, ymm11, ymm8
      vpslld ymm12, ymm11, 8
      vpsrld ymm11, ymm11, 24
      vpor ymm11, ymm11, ymm12
      vpaddd ymm10, ymm10, ymm11
      vpxor ymm9, ymm9, ymm10
      vpslld ymm12, ymm9, 7
      vpsrld ymm9, ymm9, 25
      vpor ymm9, ymm9, ymm12
      vpshufb ymm9, ymm9, ymm7
      vpshufb ymm10, ymm10, ymm6
      vpshufb ymm11, ymm11, ymm5

proc assembleChachaRounds4(): ExecutableBuffer =
  ## 4-block AVX2 rounds: two pairs in parallel (group A blocks 0,1 in
  ## ymm0..3; group B blocks 2,3 in ymm8..11). Layout per pair matches
  ## `simdRounds2`: word w of pair-block k at
  ## [(w shr 2) shl 3 + (w and 3) + 4*(k and 1)], pair 1 32 words later.
  var a = newAssembler(akX64)
  dynasm a:
    arch x64
    alias inp, rsi, rdx
    vmovdqu ymm0, [inp]
    vmovdqu ymm1, [inp + 32]
    vmovdqu ymm2, [inp + 64]
    vmovdqu ymm3, [inp + 96]
    vmovdqu ymm8, [inp + 128]
    vmovdqu ymm9, [inp + 160]
    vmovdqu ymm10, [inp + 192]
    vmovdqu ymm11, [inp + 224]
    vmovdqu ymm5, [glob("shuf39")]
    vmovdqu ymm6, [glob("shuf4e")]
    vmovdqu ymm7, [glob("shuf93")]
  emitChachaRounds4(a)
  dynasm a:
    arch x64
    alias outp, rdi, rcx
    vmovdqu [outp], ymm0
    vmovdqu [outp + 32], ymm1
    vmovdqu [outp + 64], ymm2
    vmovdqu [outp + 96], ymm3
    vmovdqu [outp + 128], ymm8
    vmovdqu [outp + 160], ymm9
    vmovdqu [outp + 192], ymm10
    vmovdqu [outp + 224], ymm11
    vzeroupper()
    ret()
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

proc assembleChachaCrypt4(): ExecutableBuffer =
  ## Fused 4-block crypt: rounds over the interleaved input at [inp],
  ## pool stored to [poolp], then (pool + input) xor plaintext stored to
  ## [dstp], all in one call. Same row-group SSE epilogue shape as the
  ## 2-block kernel (uniform regs via the pool round-trip), extended to
  ## both pairs. `din` is passed by pointer (256 B by-value copies would
  ## cost an extra full pass over the input per quad).
  var a = newAssembler(akX64)
  dynasm a:
    arch x64
    alias inp, rcx, r9
    vmovdqu ymm0, [inp]
    vmovdqu ymm1, [inp + 32]
    vmovdqu ymm2, [inp + 64]
    vmovdqu ymm3, [inp + 96]
    vmovdqu ymm8, [inp + 128]
    vmovdqu ymm9, [inp + 160]
    vmovdqu ymm10, [inp + 192]
    vmovdqu ymm11, [inp + 224]
    vmovdqu ymm5, [glob("shuf39")]
    vmovdqu ymm6, [glob("shuf4e")]
    vmovdqu ymm7, [glob("shuf93")]
  emitChachaRounds4(a)
  dynasm a:
    arch x64
    alias poolp, rdx, r8
    vmovdqu [poolp], ymm0
    vmovdqu [poolp + 32], ymm1
    vmovdqu [poolp + 64], ymm2
    vmovdqu [poolp + 96], ymm3
    vmovdqu [poolp + 128], ymm8
    vmovdqu [poolp + 160], ymm9
    vmovdqu [poolp + 192], ymm10
    vmovdqu [poolp + 224], ymm11
  # Keystream add pass (uniform regs via the pool round-trip), then one
  # vzeroupper before the SSE xor/store pass.
  for p in 0 ..< 2:
    let b = p * 128
    for g in 0 ..< 4:
      let o = b + g * 32
      dynasm a:
        arch x64
        alias poolp, rdx, r8
        alias inp, rcx, r9
        vmovdqu ymm0, [poolp + o]
        vmovdqu ymm1, [inp + o]
        vpaddd ymm0, ymm0, ymm1
        vmovdqu [poolp + o], ymm0
  dynasm a:
    arch x64
    vzeroupper()
  for p in 0 ..< 2:
    let b = p * 128
    for g in 0 ..< 4:
      let o = b + g * 32
      let o16 = o + 16
      let q = b + g * 16
      let q64 = 64 + q
      dynasm a:
        arch x64
        alias dstp, rdi, rcx
        alias srcp, rsi, rdx
        alias poolp, rdx, r8
        movdqu xmm0, [poolp + o]
        movdqu xmm1, [srcp + q]
        pxor xmm0, xmm1
        movdqu [dstp + q], xmm0
        movdqu xmm0, [poolp + o16]
        movdqu xmm1, [srcp + q64]
        pxor xmm0, xmm1
        movdqu [dstp + q64], xmm0
  dynasm a:
    arch x64
    ret()
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

var gChachaBuf4: ExecutableBuffer
var gChachaReady4: Atomic[bool]
var gChachaCrypt4Buf: ExecutableBuffer
var gChachaCrypt4Ready: Atomic[bool]

proc ensureChachaJit4() =
  if gChachaReady4.load(moAcquire):
    return
  withLock(gChachaLock):
    if gChachaReady4.load(moRelaxed):
      return
    gChachaBuf4 = assembleChachaRounds4()
    gChachaReady4.store(true, moRelease)

proc ensureChachaCrypt4Jit() =
  if gChachaCrypt4Ready.load(moAcquire):
    return
  withLock(gChachaLock):
    if gChachaCrypt4Ready.load(moRelaxed):
      return
    gChachaCrypt4Buf = assembleChachaCrypt4()
    gChachaCrypt4Ready.store(true, moRelease)

proc chacha20Rounds4Jit*(pool: var array[64, uint32],
                         din: array[64, uint32]) =
  ## Apply 20 rounds to four blocks at once (two-pair layout, pair 1
  ## 32 words after pair 0). Requires AVX2 + OS YMM support; check
  ## cpuHasAvx2() first.
  ensureChachaJit4()
  let f = cast[ChachaJitFn](gChachaBuf4.ptrAt(AssemblyOffset(0)))
  f(addr pool[0], unsafeAddr din[0])

type ChachaCrypt4Fn* = proc(dstp, srcp, poolp, inp: pointer) {.cdecl, gcsafe.}

proc chacha20Crypt4Jit*(dst, src: BytePtr, pool: var array[64, uint32],
                        din: BytePtr) =
  ## Rounds + add + xor + store for a block quad (two-pair layout, pair 1
  ## 128 bytes after pair 0; blocks land contiguously, 64 bytes each).
  ## `din` is a pointer to avoid a 256 B by-value copy per quad.
  ## Requires AVX2 + OS YMM support; check cpuHasAvx2() first.
  ensureChachaCrypt4Jit()
  let f = cast[ChachaCrypt4Fn](gChachaCrypt4Buf.ptrAt(AssemblyOffset(0)))
  f(cast[pointer](dst), cast[pointer](src), addr pool[0],
    cast[pointer](din))

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
