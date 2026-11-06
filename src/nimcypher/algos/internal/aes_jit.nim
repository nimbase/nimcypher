# Hardware AES kernels via runtime-assembled dynasm JIT: AES-NI on amd64,
# ARMv8 Crypto Extensions on arm64.
#
# Mirrors `internal/aes_simd` batch shapes (8 independent blocks per
# kernel, round keys streamed from the caller's byte-image schedule):
# three encrypt, three decrypt, and three CTR-crypt kernels (10/12/14
# rounds), assembled once and cached process-wide. No `nimsimd`, no
# whole-binary `-maes` passC flag. The scalar bitsliced path in
# `../aes` stays the reference.
#
# ARM note: dynasm has no crypto mnemonics yet, so the four 2-operand
# instructions (aese/aesd/aesmc/aesimc) are emitted as raw words via
# `armCryptoWord` (bases pinned against clang by tests/taes_jit
# "arm64 crypto word goldens"). Everything else (ldr/str Q, eor,
# integer/stack/branch) goes through the regular `arch aarch64` DSL,
# which cannot take dynamic vector indices — the eight states are
# spelled out as v0..v7 (key in v31, ctr scratch in v30).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64) and not defined(arm64):
  {.error: "aes_jit currently requires amd64 or arm64.".}

import ../common
import dynasm
import std/locks
import std/atomics

const aesJitBatch* = 8

type
  AesJitEncFn* = proc(nrk, dst, src: pointer) {.cdecl, gcsafe.}
  AesJitDecFn* = proc(nrk, nrkInv, dst, src: pointer) {.cdecl, gcsafe.}
  AesJitCtrFn* = proc(nrk, dst, src, ctrp: pointer) {.cdecl, gcsafe.}

# ARMv8 Crypto/AES word encoders. Pure bit manipulation, compiled on
# every host so the clang-pinned goldens in tests/taes_jit run
# everywhere; the kernels that emit them are arm64-only (below).
const
  armAeseBase* = 0x4E284800'u32
  armAesdBase* = 0x4E285800'u32
  armAesmcBase* = 0x4E286800'u32
  armAesimcBase* = 0x4E287800'u32
  armLdrQBase* = 0x3DC00000'u32
  armStrQBase* = 0x3D800000'u32
  armEorVBase* = 0x6E201C00'u32 # Q bit baked in

func armCryptoWord*(base: uint32, rd, rn: int): uint32 {.inline.} =
  base or uint32(rd and 31) or (uint32(rn and 31) shl 5)

func armLdrQWord*(rt, rn: int, off: int): uint32 {.inline.} =
  armLdrQBase or uint32(rt and 31) or (uint32(rn and 31) shl 5) or
    (uint32(off shr 4 and 0xFFF) shl 10)

func armStrQWord*(rt, rn: int, off: int): uint32 {.inline.} =
  armStrQBase or uint32(rt and 31) or (uint32(rn and 31) shl 5) or
    (uint32(off shr 4 and 0xFFF) shl 10)

func armEorVWord*(rd, rn, rm: int): uint32 {.inline.} =
  armEorVBase or uint32(rd and 31) or (uint32(rn and 31) shl 5) or
    (uint32(rm and 31) shl 16)

when defined(amd64):

  proc emitAesCtrHead8*(a: var Assembler) =
    ## Build 8 GCM counter blocks at [rsp .. rsp+127] from the base block
    ## at [ctrp] (low dword big-endian at [ctrp+12]), advance that dword
    ## by 8 (mod 2^32). Caller must have reserved 128 stack bytes and
    ## declare the `ctrp` alias. Clobbers rax/r10/r11/xmm9. Scratch regs
    ## avoid all arg registers on both ABIs (see ctrCrypt prologue).
    dynasm a:
      arch x64
      alias ctrp, rcx, r9
      movdqu xmm9, [ctrp]
    for i in 0 ..< aesJitBatch:
      let d = i * 16
      dynasm a:
        arch x64
        movdqu [rsp + d], xmm9
    dynasm a:
      arch x64
      alias ctrp, rcx, r9
      # r10d = BE dword at [ctrp+12] as an integer (LE dword load would
      # give the byteswapped value, and there is no bswap mnemonic).
      movzx r10d, byte [ctrp + 12]
      `shl` r10d, 8
      movzx eax, byte [ctrp + 13]
      `or` r10d, eax
      `shl` r10d, 8
      movzx eax, byte [ctrp + 14]
      `or` r10d, eax
      `shl` r10d, 8
      movzx eax, byte [ctrp + 15]
      `or` r10d, eax
    for i in 0 ..< aesJitBatch:
      let d = i * 16
      let o12 = d + 12
      let o13 = d + 13
      let o14 = d + 14
      let o15 = d + 15
      dynasm a:
        arch x64
        mov r11d, r10d
      if i > 0:
        dynasm a:
          arch x64
          add r11d, i
      dynasm a:
        arch x64
        mov eax, r11d
        mov [rsp + o15], al
        `shr` eax, 8
        mov [rsp + o14], al
        `shr` eax, 8
        mov [rsp + o13], al
        `shr` eax, 8
        mov [rsp + o12], al
    dynasm a:
      arch x64
      alias ctrp, rcx, r9
      add r10d, 8
      mov eax, r10d
      mov [ctrp + 15], al
      `shr` eax, 8
      mov [ctrp + 14], al
      `shr` eax, 8
      mov [ctrp + 13], al
      `shr` eax, 8
      mov [ctrp + 12], al

  proc emitAesEncRounds8*(a: var Assembler, R: int) =
    ## AES-ENC key0 xor + middle rounds over the 8 states in xmm0..7
    ## (no final round; caller emits aesenclast + store). Caller declares
    ## the `nrkp` alias. Clobbers xmm8.
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

  proc assembleCtrCryptBatch8(R: int): ExecutableBuffer =
    ## CTR-crypt exactly 8 blocks for GCM: build counters base..base+7
    ## (GCM inc32 order, low dword big-endian at [ctrp+12]) on a stack
    ## scratch area, AES-encrypt them, xor with 128 bytes at [srcp],
    ## store at [dstp]. Advances the dword at [ctrp+12] by 8 (mod 2^32).
    ## Same round-key layout as the encrypt batches.
    var a = newAssembler(akX64)
    # Scratch GP regs: r10d holds the base counter, r11d the per-block
    # counter, eax the shift temp. All caller-saved and arg-free on both
    # ABIs (SysV: rdi/rsi/rdx/rcx live; Win: rcx/rdx/r8/r9 live), so no
    # saves needed. Stack slots hold the 8 counter blocks.
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
      dynasm a:
        arch x64
        alias dstp, rsi, rdx
        alias srcp, rdx, r8
        aesenclast Rx(s), xmm8
        movdqu xmm9, [srcp + d]
        pxor Rx(s), xmm9
        movdqu [dstp + d], Rx(s)
    dynasm a:
      arch x64
      add rsp, 128
      ret()
    result = a.finalize()

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
    emitAesEncRounds8(a, R)
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

when defined(arm64):
  # ARMv8 Crypto kernels. dynasm has no crypto mnemonics yet, so the
  # four 2-operand instructions (aese/aesd/aesmc/aesimc) and the
  # dynamic-index vector memory ops are emitted as raw words via the
  # `arm*Word` helpers above (bases pinned against clang by the
  # "arm64 crypto word goldens" test). Everything else (key loads,
  # integer/stack/branch) goes through the regular `arch aarch64`
  # DSL, which cannot take dynamic vector indices — the eight states
  # are the fixed set v0..v7 (round key in v31, ctr scratch in v30).
  template emitAese(a: var Assembler, rd, rn: int) =
    a.pushU32(armCryptoWord(armAeseBase, rd, rn))

  template emitAesd(a: var Assembler, rd, rn: int) =
    a.pushU32(armCryptoWord(armAesdBase, rd, rn))

  template emitAesmc(a: var Assembler, rd, rn: int) =
    a.pushU32(armCryptoWord(armAesmcBase, rd, rn))

  template emitAesimc(a: var Assembler, rd, rn: int) =
    a.pushU32(armCryptoWord(armAesimcBase, rd, rn))

  proc ldStates8(a: var Assembler, baseReg: int, off0: int) =
    ## Load the 8 states v0..v7 from [baseReg + off0 .. + 127].
    ## `baseReg` is a raw number (2 = x2 src, 3 = x3, 31 = sp).
    for i in 0 ..< aesJitBatch:
      a.pushU32(armLdrQWord(i, baseReg, off0 + i * 16))

  proc stStates8(a: var Assembler, baseReg: int, off0: int) =
    ## Store the 8 states v0..v7 to [baseReg + off0 .. + 127].
    for i in 0 ..< aesJitBatch:
      a.pushU32(armStrQWord(i, baseReg, off0 + i * 16))

  proc emitAesEncRoundsA64(a: var Assembler, R: int) =
    ## Key0 xor + middle AESE/AESMC rounds over v0..v7 (round key
    ## reloaded into v31 each round; no final round — the caller
    ## emits it, like the x64 `emitAesEncRounds8`).
    dynasm a:
      arch aarch64
      ldr q31, [x0]
    for i in 0 ..< aesJitBatch:
      a.pushU32(armEorVWord(i, i, 31))
    for r in 1 ..< R:
      let d = r * 16
      dynasm a:
        arch aarch64
        ldr q31, [x0, d]
      for i in 0 ..< aesJitBatch:
        emitAese(a, i, 31)
        emitAesmc(a, i, i)

  proc emitAesEncFinalA64(a: var Assembler, R: int) =
    ## Final AESE (no MixColumns) + xor with the last round key.
    let km1 = (R - 1) * 16
    let kd = R * 16
    dynasm a:
      arch aarch64
      ldr q31, [x0, km1]
    for i in 0 ..< aesJitBatch:
      emitAese(a, i, 31)
    dynasm a:
      arch aarch64
      ldr q31, [x0, kd]
    for i in 0 ..< aesJitBatch:
      a.pushU32(armEorVWord(i, i, 31))

  proc emitAesCtrHeadA64(a: var Assembler) =
    ## Build 8 GCM counter blocks at [sp .. sp+127] from the base
    ## block at [x3] (low dword big-endian at [x3+12]), advancing that
    ## dword by 8 (mod 2^32). Caller reserved 128 stack bytes.
    ## Clobbers w4-w6/x5-x6 (all caller-saved on AAPCS64).
    dynasm a:
      arch aarch64
      ldrb w4, [x3, 12]
      lsl w4, w4, 8
      ldrb w5, [x3, 13]
      orr w4, w4, w5
      lsl w4, w4, 8
      ldrb w5, [x3, 14]
      orr w4, w4, w5
      lsl w4, w4, 8
      ldrb w5, [x3, 15]
      orr w4, w4, w5
      ldp x5, x6, [x3]
      stp x5, x6, [sp]
      stp x5, x6, [sp, 16]
      stp x5, x6, [sp, 32]
      stp x5, x6, [sp, 48]
      stp x5, x6, [sp, 64]
      stp x5, x6, [sp, 80]
      stp x5, x6, [sp, 96]
      stp x5, x6, [sp, 112]
    for i in 0 ..< aesJitBatch:
      let s = i * 16
      dynasm a:
        arch aarch64
        add w5, w4, i
        lsr w6, w5, 24
        strb w6, [sp, s + 12]
        lsr w6, w5, 16
        strb w6, [sp, s + 13]
        lsr w6, w5, 8
        strb w6, [sp, s + 14]
        strb w5, [sp, s + 15]
    dynasm a:
      arch aarch64
      add w4, w4, 8
      lsr w5, w4, 24
      strb w5, [x3, 12]
      lsr w5, w4, 16
      strb w5, [x3, 13]
      lsr w5, w4, 8
      strb w5, [x3, 14]
      strb w4, [x3, 15]

  proc assembleEncBatch8(R: int): ExecutableBuffer =
    ## Encrypt exactly 8 blocks, R full rounds + final, keys at [x0].
    ## AAPCS64 args: x0 = nrk, x1 = dst, x2 = src.
    var a = newAssembler(akAarch64)
    ldStates8(a, 2, 0)
    emitAesEncRoundsA64(a, R)
    emitAesEncFinalA64(a, R)
    stStates8(a, 1, 0)
    dynasm a:
      arch aarch64
      ret()
    result = a.finalize()

  proc assembleDecBatch8(R: int): ExecutableBuffer =
    ## Decrypt exactly 8 blocks via the equivalent inverse cipher:
    ## first AESD with the last round key, middle rounds from the
    ## InvMixColumns schedule, final xor with the first key.
    ## Args: x0 = nrk, x1 = nrkInv, x2 = dst, x3 = src.
    var a = newAssembler(akAarch64)
    ldStates8(a, 3, 0)
    let kd = R * 16
    dynasm a:
      arch aarch64
      ldr q31, [x0, kd]
    for i in 0 ..< aesJitBatch:
      emitAesd(a, i, 31)
    for r in countdown(R - 1, 1):
      for i in 0 ..< aesJitBatch:
        emitAesimc(a, i, i)
      let d = r * 16
      dynasm a:
        arch aarch64
        ldr q31, [x1, d]
      for i in 0 ..< aesJitBatch:
        emitAesd(a, i, 31)
    dynasm a:
      arch aarch64
      ldr q31, [x0]
    for i in 0 ..< aesJitBatch:
      a.pushU32(armEorVWord(i, i, 31))
    stStates8(a, 2, 0)
    dynasm a:
      arch aarch64
      ret()
    result = a.finalize()

  proc assembleCtrCryptBatch8(R: int): ExecutableBuffer =
    ## CTR-crypt exactly 8 blocks for GCM: build counters base..base+7
    ## on a 128-byte stack area, AES-encrypt them, xor with 128 bytes
    ## at [x2], store at [x1]. Advances the dword at [x3+12] by 8.
    ## Args: x0 = nrk, x1 = dst, x2 = src, x3 = ctrp.
    var a = newAssembler(akAarch64)
    dynasm a:
      arch aarch64
      sub sp, sp, 128
    emitAesCtrHeadA64(a)
    ldStates8(a, 31, 0)
    emitAesEncRoundsA64(a, R)
    emitAesEncFinalA64(a, R)
    for i in 0 ..< aesJitBatch:
      let d = i * 16
      dynasm a:
        arch aarch64
        ldr q30, [x2, d]
      a.pushU32(armEorVWord(i, i, 30))
      a.pushU32(armStrQWord(i, 1, d))
    dynasm a:
      arch aarch64
      add sp, sp, 128
      ret()
    result = a.finalize()

var gAesLock: Lock
initLock(gAesLock) # module init runs single-threaded at startup
var gAesEnc: array[3, ExecutableBuffer]
var gAesDec: array[3, ExecutableBuffer]
var gAesCtr: array[3, ExecutableBuffer]
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
      gAesCtr[idx] = assembleCtrCryptBatch8(jitRounds[idx])
    gAesReady.store(true, moRelease)

proc aesJitAvailable*(): bool =
  ## True once all nine kernels assembled (false only if exec memory is
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

proc ctrCrypt8Jit*(rounds: int, nrk: pointer, dst, src, ctrp: BytePtr) =
  ## CTR-crypt exactly 8 blocks: keystream from counters at `ctrp`
  ## (advanced by 8 in memory), xored with `src` into `dst`.
  ensureAesJit()
  let f = cast[AesJitCtrFn](
    gAesCtr[aesRoundsIndex(rounds)].ptrAt(AssemblyOffset(0)))
  f(nrk, cast[pointer](dst), cast[pointer](src), cast[pointer](ctrp))

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
