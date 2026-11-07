# Runtime CPU feature gates for dynasm JIT kernels (amd64 only).
#
# CPUID alone is not enough for AVX/AVX2: the OS must save/restore YMM
# state (OSXSAVE + XCR0 via XGETBV). These gates assemble tiny detectors
# with dynasm itself (cpuid/xgetbv mnemonics) and additionally run a
# functional smoke test, since at least one host class misexecutes
# certain VEX forms even with the right CPUID bits (cf. mulx).
# Results are cached process-wide.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "cpu_jit currently requires amd64.".}

import dynasm
import std/locks
import std/atomics

var gCpuLock: Lock
initLock(gCpuLock)
var gAvx2State: Atomic[int] # -1 unknown, 0 no, 1 yes
gAvx2State.store(-1, moRelaxed)

proc detectAvx2(): bool =
  ## One-shot detector; may raise on assembly/exec failure.
  # CPUID.07:EBX[5] + CPUID.01:ECX[27] (OSXSAVE) + XCR0[2:1].
  var a = newAssembler(akX64)
  dynasm a:
    arch x64
    push rbx
    mov eax, 7
    `xor` ecx, ecx
    cpuid()
    mov edx, 32 # 1 shl 5
    test ebx, edx
    setnz al # avx2 bit
    movzx esi, al # park (2nd cpuid destroys eax)
    mov eax, 1
    cpuid()
    mov edx, 0x08000000 # 1 shl 27
    test ecx, edx
    setnz cl # osxsave bit
    movzx edi, cl # park (xgetbv needs ecx = 0)
    `xor` ecx, ecx
    xgetbv() # xcr0 -> edx:eax
    `and` eax, 6
    cmp eax, 6
    setz dl # SSE+AVX state bits
    movzx edx, dl # park
    `and` esi, edi
    `and` esi, edx
    mov eax, esi
    pop rbx
    ret()
  var buf = a.finalize()
  type CpuidFn = proc(): int32 {.cdecl.}
  let f = cast[CpuidFn](buf.ptrAt(AssemblyOffset(0)))
  let r = f()
  buf.destroy()
  if r == 0:
    return false
  # Functional smoke test: vpaddd ymm (the workhorse op).
  var b = newAssembler(akX64)
  var x = [1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var y = [2'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           3'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var o: array[32, uint8]
  dynasm b:
    arch x64
    alias aptr, rdi, rcx
    alias bptr, rsi, rdx
    alias outptr, rdx, r8
    vmovdqu ymm0, [aptr]
    vmovdqu ymm1, [bptr]
    vpaddd ymm0, ymm0, ymm1
    vmovdqu [outptr], ymm0
    vzeroupper()
    ret()
  var buf2 = b.finalize()
  type ArithFn = proc(a, b, c: pointer) {.cdecl.}
  cast[ArithFn](buf2.ptrAt(AssemblyOffset(0)))(addr x, addr y, addr o)
  buf2.destroy()
  o[0] == 3 and o[16] == 3

proc cpuHasAvx2*(): bool =
  ## AVX2 with OS YMM support, verified functionally.
  if gAvx2State.load(moAcquire) >= 0:
    return gAvx2State.load(moRelaxed) == 1
  var ok = false
  try:
    acquire(gCpuLock)
    try:
      if gAvx2State.load(moRelaxed) < 0:
        ok = detectAvx2()
        gAvx2State.store(if ok: 1 else: 0, moRelease)
      else:
        ok = gAvx2State.load(moRelaxed) == 1
    finally:
      release(gCpuLock)
  except CatchableError:
    ok = false
  ok
