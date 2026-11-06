# SIMD BLAKE2b compression via runtime-assembled dynasm JIT (amd64 only).
#
# Same contract as `compress4` in `internal/blake2b_simd`: four lanes in
# one AVX2 register, 12 rounds with sigma-indexed message words. State
# v0..v14 lives in ymm0..ymm14 for the whole kernel; v15 is homed in
# its own output slot (`[statep + 480]`) and shuttled through ymm15 only
# for its two column/diagonal groups (ymm15 doubles as the rot63
# scratch everywhere else — d is dead by then). Message words stream
# from the transposed `msg` buffer; rot16/rot24 go through VEX
# `vpshufb` pool (its mem form misexecutes on at least one host class).
# rot32 through `vpshufd 0x4E` needs no scratch; rot16/24/63 go through
# shifts+OR with a shuttled scratch register (see below).
#
# The transposed `st`/`msg` buffers and the masked final xor stay Nim
# code (same shape as the scalar path); only the 12 rounds execute JIT.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "blake2b_jit currently requires amd64.".}

import ../common
import dynasm
import std/locks
import std/atomics

const b2G4: array[8, array[4, int]] = [
  [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
  [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]

const blake2bJitRounds* {.intdefine.} = 12

proc assembleBlake2bRounds(): ExecutableBuffer =
  ## State v2..v14 resident; v0/v1/v15 shuttle through their `st` slots
  ## (ymm0/ymm1/ymm15 double as rot scratch exactly when the homed
  ## value is dead — see per-tuple rules below). No pool, no stack.
  var a = newAssembler(akX64)
  # v2..v14 resident (v0, v1, v15 stay homed in st[0], st[1], st[15]).
  for i in 2 ..< 15:
    let d = i * 32
    let s = i
    dynasm a:
      arch x64
      alias statep, rdi, rcx
      vmovdqu Ry(s), [statep + d]
  for r in 0 ..< blake2bJitRounds:
    for k in 0 ..< 8:
      let ia = b2G4[k][0]
      let ib = b2G4[k][1]
      let ic = b2G4[k][2]
      let id = b2G4[k][3]
      let sx = int(blake2bSigma[r][2 * k]) * 32
      let sy = int(blake2bSigma[r][2 * k + 1]) * 32
      let usesV0 = ia == 0 or ib == 0 or ic == 0 or id == 0
      let usesV1 = ia == 1 or ib == 1 or ic == 1 or id == 1
      let usesV15 = id == 15
      # Rot scratch: ymm1 when v0 is live, else ymm0 (v0/v1 never
      # co-occur in one group; v15 uses its own shuttle).
      if usesV0:
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          vmovdqu ymm0, [statep]
      if usesV1:
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          vmovdqu ymm1, [statep + 32]
      if usesV15:
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          vmovdqu ymm15, [statep + 480]
      # head: a += b + x; d = rot32(d^a); c += d; b = rot24(b^c);
      #       a += b + y; d = rot16(d^a); c += d
      if usesV0:
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          alias msgp, rsi, rdx
          vpaddq Ry(ia), Ry(ia), Ry(ib)
          vpaddq Ry(ia), Ry(ia), [msgp + sx]
          vpxor Ry(id), Ry(id), Ry(ia)
          # rot32 via shifts (vpshufd ymm misexecutes on at least one
          # host class, like mulx and VEX vpshufb-mem)
          vmovdqu ymm1, Ry(id)
          vpsrlq ymm1, ymm1, 32
          vpsllq Ry(id), Ry(id), 32
          vpor Ry(id), Ry(id), ymm1
          vpaddq Ry(ic), Ry(ic), Ry(id)
          vpxor Ry(ib), Ry(ib), Ry(ic)
          vmovdqu ymm1, Ry(ib)
          vpsrlq ymm1, ymm1, 24
          vpsllq Ry(ib), Ry(ib), 40
          vpor Ry(ib), Ry(ib), ymm1
          vpaddq Ry(ia), Ry(ia), Ry(ib)
          vpaddq Ry(ia), Ry(ia), [msgp + sy]
          vpxor Ry(id), Ry(id), Ry(ia)
          vmovdqu ymm1, Ry(id)
          vpsrlq ymm1, ymm1, 16
          vpsllq Ry(id), Ry(id), 48
          vpor Ry(id), Ry(id), ymm1
          vpaddq Ry(ic), Ry(ic), Ry(id)
          vmovdqu [statep + 0], ymm0
      else:
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          alias msgp, rsi, rdx
          vpaddq Ry(ia), Ry(ia), Ry(ib)
          vpaddq Ry(ia), Ry(ia), [msgp + sx]
          vpxor Ry(id), Ry(id), Ry(ia)
          # rot32 via shifts (see above)
          vmovdqu ymm0, Ry(id)
          vpsrlq ymm0, ymm0, 32
          vpsllq Ry(id), Ry(id), 32
          vpor Ry(id), Ry(id), ymm0
          vpaddq Ry(ic), Ry(ic), Ry(id)
          vpxor Ry(ib), Ry(ib), Ry(ic)
          vmovdqu ymm0, Ry(ib)
          vpsrlq ymm0, ymm0, 24
          vpsllq Ry(ib), Ry(ib), 40
          vpor Ry(ib), Ry(ib), ymm0
          vpaddq Ry(ia), Ry(ia), Ry(ib)
          vpaddq Ry(ia), Ry(ia), [msgp + sy]
          vpxor Ry(id), Ry(id), Ry(ia)
          vmovdqu ymm0, Ry(id)
          vpsrlq ymm0, ymm0, 16
          vpsllq Ry(id), Ry(id), 48
          vpor Ry(id), Ry(id), ymm0
          vpaddq Ry(ic), Ry(ic), Ry(id)
          vmovdqu [statep + 32], ymm1
      if usesV15:
        # d is dead from here; home v15, then scratch is free.
        dynasm a:
          arch x64
          alias statep, rdi, rcx
          vmovdqu [statep + 480], ymm15
      # tail: b ^= c; b = rot63(b)
      if usesV0:
        dynasm a:
          arch x64
          vpxor Ry(ib), Ry(ib), Ry(ic)
          vmovdqu ymm1, Ry(ib)
          vpsrlq ymm1, ymm1, 63
          vpsllq Ry(ib), Ry(ib), 1
          vpor Ry(ib), Ry(ib), ymm1
      else:
        dynasm a:
          arch x64
          vpxor Ry(ib), Ry(ib), Ry(ic)
          vmovdqu ymm0, Ry(ib)
          vpsrlq ymm0, ymm0, 63
          vpsllq Ry(ib), Ry(ib), 1
          vpor Ry(ib), Ry(ib), ymm0
  for i in 2 ..< 15:
    let d = i * 32
    let s = i
    dynasm a:
      arch x64
      alias statep, rdi, rcx
      vmovdqu [statep + d], Ry(s)
  dynasm a:
    arch x64
    ret()
  result = a.finalize()

type Blake2bJitFn* = proc(st, msg: pointer) {.cdecl, gcsafe.}

var gB2Lock: Lock
initLock(gB2Lock) # module init runs single-threaded at startup
var gB2Buf: ExecutableBuffer
var gB2Ready: Atomic[bool]

proc ensureBlake2bJit() =
  if gB2Ready.load(moAcquire):
    return
  withLock(gB2Lock):
    if gB2Ready.load(moRelaxed):
      return
    gB2Buf = assembleBlake2bRounds()
    gB2Ready.store(true, moRelease)

proc blake2bJitAvailable*(): bool =
  try:
    ensureBlake2bJit()
  except CatchableError:
    return false
  true

proc blake2bRoundsJit*(st: var array[16, array[4, uint64]],
                       msg: array[16, array[4, uint64]]) =
  ## 12 BLAKE2b rounds in place over the interleaved `st` buffer
  ## (lanes = the four messages), message words from `msg`.
  ensureBlake2bJit()
  let f = cast[Blake2bJitFn](gB2Buf.ptrAt(AssemblyOffset(0)))
  f(addr st[0], unsafeAddr msg[0])

proc compress4Jit*(hashes: var array[4, array[8, uint64]],
                   offsets: array[4, array[2, uint64]],
                   blocks: array[4, array[16, uint64]],
                   laneMask: uint64) =
  ## Drop-in for `compress4`: interleave, JIT rounds, masked final xor.
  ## Dead lanes keep their hash (masked out of the final xor).
  var st: array[16, array[4, uint64]]
  var msg: array[16, array[4, uint64]]
  for k in 0 ..< 4:
    for j in 0 ..< 8:
      st[j][k] = hashes[k][j]
    for j in 0 ..< 16:
      msg[j][k] = blocks[k][j]
    st[8][k] = blake2bIv[0]
    st[9][k] = blake2bIv[1]
    st[10][k] = blake2bIv[2]
    st[11][k] = blake2bIv[3]
    st[12][k] = blake2bIv[4] xor offsets[k][0]
    st[13][k] = blake2bIv[5] xor offsets[k][1]
    st[14][k] = blake2bIv[6] # never the last block (as in compress4)
    st[15][k] = blake2bIv[7]
  blake2bRoundsJit(st, msg)
  for k in 0 ..< 4:
    let lk = if (laneMask and (1'u64 shl k)) != 0: 0xffffffffffffffff'u64
             else: 0'u64
    for j in 0 ..< 8:
      hashes[k][j] = hashes[k][j] xor (lk and (st[j][k] xor st[8 + j][k]))
