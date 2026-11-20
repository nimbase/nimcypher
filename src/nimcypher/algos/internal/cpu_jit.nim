# Runtime CPU feature gates for dynasm JIT kernels.
#
# amd64: AVX2 with OS YMM support (CPUID.07:EBX[5] + CPUID.01:ECX[27]
#   OSXSAVE + XCR0 via XGETBV), plus a functional vpaddd smoke test, since
#   at least one host class misexecutes certain VEX forms even with the
#   right CPUID bits (cf. mulx).
# arm64: ARMv8 Crypto Extensions (AESE/AESD + AESMC/AESIMC) for the AES JIT
#   kernels in `internal/aes_jit` — the only JIT backend on arm64. Two
#   layers: the OS-sanctioned feature query first, then a functional AESE
#   smoke test assembled with dynasm itself (backstop for misexecuting
#   hosts and heterogeneous SoCs, mirroring the x64 style).
#   - Linux: getauxval(AT_HWCAP) & HWCAP_AES. HWCAP_AES is defined as
#     ID_AA64ISAR0_EL1.AES == 0b0001 (kernel Documentation/arch/arm64/
#     elf_hwcaps.rst); the same doc warns that executing a missing
#     extension is unpredictable — not guaranteed SIGILL — so the query
#     gates any execution. (HWCAP_AES = 1 shl 3, AT_HWCAP = 16: stable
#     UAPI in arch/arm64/include/uapi/asm/hwcap.h.)
#   - macOS: always true. macOS arm64 only runs on Apple Silicon, which
#     always has FEAT_AES; no query needed.
#   - Other OSes: false (scalar fallback). Safe direction: a wrong true
#     would SIGILL inside JITted AES.
# Results are cached process-wide.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64) and not defined(arm64):
  {.error: "cpu_jit currently requires amd64 or arm64.".}

import dynasm
import std/locks
import std/atomics

var gCpuLock: Lock
initLock(gCpuLock) # module init runs single-threaded at startup

when defined(amd64):
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

elif defined(arm64):
  var gArmCryptoState: Atomic[int] # -1 unknown, 0 no, 1 yes
  gArmCryptoState.store(-1, moRelaxed)

  when defined(linux):
    proc linuxGetauxval(t: culong): culong
        {.importc: "getauxval", header: "<sys/auxv.h>".}
    const
      AT_HWCAP = 16.culong
      HWCAP_AES = 8.culong # 1 shl 3: AESE/AESD + AESMC/AESIMC
    proc osHasArmCrypto(): bool =
      (linuxGetauxval(AT_HWCAP) and HWCAP_AES) != 0
  elif defined(macosx):
    # macOS arm64 only runs on Apple Silicon, which always has FEAT_AES.
    proc osHasArmCrypto(): bool = true
  else:
    # No sanctioned query on this OS: refuse, take the scalar path.
    proc osHasArmCrypto(): bool = false

  # AESE v0.16b, v1.16b. Same word `aes_jit` emits for that pair
  # (duplicated, not imported, to keep the aes_jit -> cpu_jit edge
  # one-directional); pinned against clang by the "arm64 crypto word
  # goldens" test in tests/taes_jit.
  const armAeseV0V1 = 0x4E284820'u32

  proc detectArmCrypto(): bool =
    ## One-shot detector; may raise on assembly/exec failure. The hwcap
    ## query runs first: on a core without the extension, executing AESE
    ## is architecturally unpredictable (kernel elf_hwcaps.rst), so it
    ## must never be the probe.
    if not osHasArmCrypto():
      return false
    var a = newAssembler(akAarch64)
    var input: array[16, byte] # zeros
    var key: array[16, byte] # zeros
    var output: array[16, byte]
    dynasm a:
      arch aarch64
      ldr q0, [x0]
      ldr q1, [x2]
    a.pushU32(armAeseV0V1)
    dynasm a:
      arch aarch64
      str q0, [x1]
      ret()
    var buf = a.finalize()
    type AeseFn = proc(a, b, k: pointer) {.cdecl.}
    cast[AeseFn](buf.ptrAt(AssemblyOffset(0)))(
      addr input[0], addr output[0], addr key[0])
    buf.destroy()
    # AESE(0, 0): SubBytes(0x00) = 0x63, ShiftRows is a no-op on a
    # uniform state, AddRoundKey(0) is identity.
    for b in output:
      if b != 0x63:
        return false
    true

  proc cpuHasArmCrypto*(): bool =
    ## ARMv8 Crypto Extensions present and functionally verified.
    if gArmCryptoState.load(moAcquire) >= 0:
      return gArmCryptoState.load(moRelaxed) == 1
    var ok = false
    try:
      acquire(gCpuLock)
      try:
        if gArmCryptoState.load(moRelaxed) < 0:
          ok = detectArmCrypto()
          gArmCryptoState.store(if ok: 1 else: 0, moRelease)
        else:
          ok = gArmCryptoState.load(moRelaxed) == 1
      finally:
        release(gCpuLock)
    except CatchableError:
      ok = false
    ok
