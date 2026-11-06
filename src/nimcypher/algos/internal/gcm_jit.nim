# Fused AES-CTR + GHASH kernel for GCM bulk paths (amd64 only).
#
# One call crypts 8 blocks: in-kernel counter build, AES rounds, xor
# with plaintext, store ciphertext, then the aggregated GHASH fold over
# the just-stored blocks with a single reduction. Halves the indirect
# calls per message vs CTR+AGG separately, keeps the 128 B chunk hot,
# and lets the CPU overlap the next AES batch with the previous GHASH
# chain (independent registers, acc carried in memory).
#
# Built from the shared emitters (`emitAesCtrHead8`,
# `emitAesEncRounds8`, `emitGhashAgg8`) so theRoots stay in one place;
# register/alias contracts are documented on each emitter. All
# instructions are legacy-encoded host-verified forms (AESENC,
# PCLMULQDQ, SSE shuffles/shifts) — no VEX anywhere, so no
# vzeroupper or transition penalties.
#
# Calling convention: (nrk, src, dst, blk) for seal, (nrk, dst, src,
# blk) for open, with blk pointing at {ctr[16], acc[16], pow[8][16]} —
# those GcmContext fields are laid out contiguously for exactly this
# reason. The order is deliberate: with the fold input in the 3rd slot
# in both cases, the shared GHASH emitter's `srcp` (rdx on SysV, r8 on
# Windows) reads the ciphertext in both cases (stored dst for seal,
# source src for open), so no extra moves are needed between the AES
# and GHASH halves. The kernel advances [blk] ctr by 8 (GCM inc32) and
# folds into [blk+16] acc. Rounds variants (10/12/14, seal+open) are
# assembled once and cached process-wide.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "gcm_jit currently requires amd64.".}

import ../common
import ./aes_jit
import ./ghash_jit
import dynasm
import std/locks
import std/atomics

proc assembleGcmCrypt8(R: int, forDecrypt: bool): ExecutableBuffer =
  ## forDecrypt=false (seal): args (nrk, src, dst, blk); the GHASH half
  ## folds the ciphertext just stored to dst.
  ## forDecrypt=true (open): args (nrk, dst, src, blk); identical code
  ## except dst/src slots swap, so the GHASH half folds the ciphertext
  ## read from src while the plaintext goes to dst.
  var a = newAssembler(akX64)
  # Frame: 128 B of counter slots. The GHASH half needs acc/pow/srcp
  # in the shared emitter's registers (rdi/rsi/rdx on SysV,
  # rcx/rdx/r8 on Windows); all three become free after the AES final
  # (nrk/src dead, dst already in srcp's slot by arg order), so plain
  # moves rebind them — no extra saved regs needed.
  dynasm a:
    arch x64
    sub rsp, 128
  emitAesCtrHead8(a)
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    dynasm a:
      arch x64
      movdqu Rx(s), [rsp + d]
  emitAesEncRounds8(a, R)
  let kd = R * 16
  dynasm a:
    arch x64
    alias nrkp, rdi, rcx
    movdqu xmm8, [nrkp + kd]
  for i in 0 ..< aesJitBatch:
    let s = i
    let d = i * 16
    if forDecrypt:
      dynasm a:
        arch x64
        alias dstp, rsi, rdx
        alias srcp, rdx, r8
        aesenclast Rx(s), xmm8
        movdqu xmm9, [srcp + d]
        pxor Rx(s), xmm9
        movdqu [dstp + d], Rx(s)
    else:
      dynasm a:
        arch x64
        alias dstp, rdx, r8
        alias srcp, rsi, rdx
        aesenclast Rx(s), xmm8
        movdqu xmm9, [srcp + d]
        pxor Rx(s), xmm9
        movdqu [dstp + d], Rx(s)
  # GHASH over the just-stored ciphertext: by arg order (nrk, src, dst,
  # blk) the shared emitter's srcp (rdx/r8) already reads dst. Rebind
  # accp/powp from the (now dead) nrk/src slots; blk itself is still
  # intact in rcx/r9 (the AES half uses no GP regs besides rax/r10/r11).
  when defined(windows):
    dynasm a:
      arch x64
      alias blkp, rcx, r9
      mov rcx, blkp
      add rcx, 16
      mov rdx, blkp
      add rdx, 32
  else:
    dynasm a:
      arch x64
      alias blkp, rcx, r9
      mov rdi, blkp
      add rdi, 16
      mov rsi, blkp
      add rsi, 32
  emitGhashAgg8(a)
  dynasm a:
    arch x64
    add rsp, 128
    ret()
    global bswapidx
    u8 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  result = a.finalize()

type GcmCryptFn* = proc(nrk, a, b, blk: pointer) {.cdecl, gcsafe.}
  ## Positional: (nrk, src, dst, blk) for seal, (nrk, dst, src, blk) for
  ## open — the kernel folds its 3rd argument in both cases.

var gGcmLock: Lock
initLock(gGcmLock)
var gGcmEnc: array[3, ExecutableBuffer]
var gGcmDec: array[3, ExecutableBuffer]
var gGcmReady: Atomic[bool]

proc gcmRoundsIndex(rounds: int): int =
  if rounds < 10 or rounds > 14 or (rounds and 1) == 1:
    raise newException(ValueError, "gcm_jit needs 10/12/14 rounds")
  (rounds div 2) - 5

proc ensureGcmJit() =
  if gGcmReady.load(moAcquire):
    return
  withLock(gGcmLock):
    if gGcmReady.load(moRelaxed):
      return
    const jitRounds = [10, 12, 14]
    for idx in 0 ..< 3:
      gGcmEnc[idx] = assembleGcmCrypt8(jitRounds[idx], false)
      gGcmDec[idx] = assembleGcmCrypt8(jitRounds[idx], true)
    gGcmReady.store(true, moRelease)

proc gcmCrypt8JitAvailable*(): bool =
  try:
    ensureGcmJit()
  except CatchableError:
    return false
  true

proc gcmCrypt8Jit*(rounds: int, nrk: pointer, dst, src, blk: BytePtr,
                    decrypt: bool = false) =
  ## Crypt exactly 8 blocks through (nrk/rounds) with GCM counter state
  ## at `blk` ({ctr, acc, pow} block, see module header). Advances ctr
  ## by 8, folds into acc. Seal folds the ciphertext written to dst;
  ## open (`decrypt=true`) folds the ciphertext read from src.
  ensureGcmJit()
  let idx = gcmRoundsIndex(rounds)
  if decrypt:
    let f = cast[GcmCryptFn](gGcmDec[idx].ptrAt(AssemblyOffset(0)))
    f(nrk, cast[pointer](dst), cast[pointer](src), cast[pointer](blk))
  else:
    let f = cast[GcmCryptFn](gGcmEnc[idx].ptrAt(AssemblyOffset(0)))
    f(nrk, cast[pointer](src), cast[pointer](dst), cast[pointer](blk))
