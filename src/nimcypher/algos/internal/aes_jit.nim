# Hardware AES kernels via runtime-assembled dynasm JIT (amd64 only).
#
# Mirrors `internal/aes_simd` batch shapes (8 independent blocks per
# kernel, round keys streamed from the caller's byte-image schedule):
# three encrypt and three decrypt kernels (10/12/14 rounds), assembled
# once and cached process-wide. No `nimsimd`, no whole-binary `-maes`
# passC flag. The scalar bitsliced path in `../aes` stays the reference.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "aes_jit currently requires amd64.".}

import ../common
import dynasm
import std/locks
import std/atomics

const aesJitBatch* = 8

type
  AesJitEncFn* = proc(nrk, dst, src: pointer) {.cdecl, gcsafe.}
  AesJitDecFn* = proc(nrk, nrkInv, dst, src: pointer) {.cdecl, gcsafe.}

proc assembleEncBatch8(R: int): ExecutableBuffer =
  ## Encrypt exactly 8 blocks, R full rounds + final, keys at [nrkp].
  var a = newAssembler(akX64)
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    dynasm a:
      arch x64
      alias srcp, rdx, r8
      movdqu Rx(s), [srcp + d]
  dynasm a:
    arch x64
    alias nrkp, rdi, rcx
    movdqu xmm8, [nrkp]
  for i in 0 ..< aesJitBatch:
    let s = i
    dynasm a:
      arch x64
      pxor Rx(s), xmm8
  for r in 1 ..< R:
    let d = r * 16
    dynasm a:
      arch x64
      alias nrkp, rdi, rcx
      movdqu xmm8, [nrkp + d]
    for i in 0 ..< aesJitBatch:
      let s = i
      dynasm a:
        arch x64
        aesenc Rx(s), xmm8
  let kd = R * 16
  dynasm a:
    arch x64
    alias nrkp, rdi, rcx
    movdqu xmm8, [nrkp + kd]
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    dynasm a:
      arch x64
      alias dstp, rsi, rdx
      aesenclast Rx(s), xmm8
      movdqu [dstp + d], Rx(s)
  dynasm a:
    arch x64
    ret()
  result = a.finalize()

proc assembleDecBatch8(R: int): ExecutableBuffer =
  ## Decrypt exactly 8 blocks via the equivalent inverse cipher:
  ## first AESDEC with the last round key, middle rounds from the
  ## InvMixColumns schedule, final AESDECLAST with the first key.
  var a = newAssembler(akX64)
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    dynasm a:
      arch x64
      alias srcp, rcx, r9
      movdqu Rx(s), [srcp + d]
  let kd = R * 16
  dynasm a:
    arch x64
    alias nrkp, rdi, rcx
    movdqu xmm8, [nrkp + kd]
  for i in 0 ..< aesJitBatch:
    let s = i
    dynasm a:
      arch x64
      pxor Rx(s), xmm8
  for r in countdown(R - 1, 1):
    let d = r * 16
    dynasm a:
      arch x64
      alias invp, rsi, rdx
      movdqu xmm8, [invp + d]
    for i in 0 ..< aesJitBatch:
      let s = i
      dynasm a:
        arch x64
        aesdec Rx(s), xmm8
  dynasm a:
    arch x64
    alias nrkp, rdi, rcx
    movdqu xmm8, [nrkp]
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    dynasm a:
      arch x64
      alias dstp, rdx, r8
      aesdeclast Rx(s), xmm8
      movdqu [dstp + d], Rx(s)
  dynasm a:
    arch x64
    ret()
  result = a.finalize()

var gAesLock: Lock
initLock(gAesLock) # module init runs single-threaded at startup
var gAesEnc: array[3, ExecutableBuffer]
var gAesDec: array[3, ExecutableBuffer]
var gAesReady: Atomic[bool]

proc aesRoundsIndex(rounds: int): int =
  ## 10/12/14 -> slot 0/1/2. initAes only produces these.
  if rounds < 10 or rounds > 14 or (rounds and 1) == 1:
    raise newException(ValueError, "aes_jit needs 10/12/14 rounds")
  (rounds div 2) - 5

proc ensureAesJit() =
  if gAesReady.load(moAcquire):
    return
  withLock(gAesLock):
    if gAesReady.load(moRelaxed):
      return
    const jitRounds = [10, 12, 14]
    for idx in 0 ..< 3:
      gAesEnc[idx] = assembleEncBatch8(jitRounds[idx])
      gAesDec[idx] = assembleDecBatch8(jitRounds[idx])
    gAesReady.store(true, moRelease)

proc aesJitAvailable*(): bool =
  ## True once all six kernels assembled (false only if exec memory is
  ## unavailable — caller falls back to simd/scalar).
  try:
    ensureAesJit()
  except CatchableError:
    return false
  true

proc encBatch8Jit*(rounds: int, nrk: pointer, dst, src: BytePtr) =
  ensureAesJit()
  let f = cast[AesJitEncFn](
    gAesEnc[aesRoundsIndex(rounds)].ptrAt(AssemblyOffset(0)))
  f(nrk, cast[pointer](dst), cast[pointer](src))

proc decBatch8Jit*(rounds: int, nrk, nrkInv: pointer, dst,
                   src: BytePtr) =
  ensureAesJit()
  let f = cast[AesJitDecFn](
    gAesDec[aesRoundsIndex(rounds)].ptrAt(AssemblyOffset(0)))
  f(nrk, nrkInv, cast[pointer](dst), cast[pointer](src))

proc encryptBlocksJit*(rounds: int, nrk: pointer, dst, src: BytePtr,
                       nb: int) =
  ## Encrypt `nb` blocks (`nb >= 1`); tail batch pads by replication.
  ensureAesJit()
  let idx = aesRoundsIndex(rounds)
  let f = cast[AesJitEncFn](gAesEnc[idx].ptrAt(AssemblyOffset(0)))
  var off = 0
  var left = nb
  while left >= aesJitBatch:
    f(nrk, cast[pointer](dst + off * 16), cast[pointer](src + off * 16))
    off += aesJitBatch
    left -= aesJitBatch
  if left > 0:
    var inp, outp: array[aesJitBatch * 16, byte]
    copyMem(addr inp[0], src + off * 16, left * 16)
    var p = left * 16
    while p < inp.len:
      let take = min(left * 16, inp.len - p)
      copyMem(addr inp[p], addr inp[0], take)
      p += take
    f(nrk, cast[pointer](addr outp[0]), cast[pointer](addr inp[0]))
    copyMem(dst + off * 16, addr outp[0], left * 16)
    wipe(inp)
    wipe(outp)

proc decryptBlocksJit*(rounds: int, nrk, nrkInv: pointer, dst,
                       src: BytePtr, nb: int) =
  ## Decrypt `nb` blocks (`nb >= 1`).
  ensureAesJit()
  let idx = aesRoundsIndex(rounds)
  let f = cast[AesJitDecFn](gAesDec[idx].ptrAt(AssemblyOffset(0)))
  var off = 0
  var left = nb
  while left >= aesJitBatch:
    f(nrk, nrkInv, cast[pointer](dst + off * 16),
      cast[pointer](src + off * 16))
    off += aesJitBatch
    left -= aesJitBatch
  if left > 0:
    var inp, outp: array[aesJitBatch * 16, byte]
    copyMem(addr inp[0], src + off * 16, left * 16)
    var p = left * 16
    while p < inp.len:
      let take = min(left * 16, inp.len - p)
      copyMem(addr inp[p], addr inp[0], take)
      p += take
    f(nrk, nrkInv, cast[pointer](addr outp[0]),
      cast[pointer](addr inp[0]))
    copyMem(dst + off * 16, addr outp[0], left * 16)
    wipe(inp)
    wipe(outp)
