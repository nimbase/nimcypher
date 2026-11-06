# 64x64->128-bit multiply via runtime-assembled dynasm JIT (amd64 only).
#
# Drop-in for `mulWide` in `internal/montgomery64`: one MULX (BMI2)
# gives lo+hi without touching flags. Assemble-once, process-lifetime
# cache behind the usual global lock + atomic publish.
#
# Execution is gated on a functional self-test, not just CPUID: at
# least one host class runs MULX with the wrong data flow (SRC ignored,
# RDX read) even for clang-identical bytes, so `mulwideJitAvailable`
# JIT-checks 2*3 and reports false there — callers must fall back to
# the portable splitting multiply (never to another MULX path).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "mulwide_jit currently requires amd64.".}

import dynasm
import std/locks
import std/atomics

proc assembleMulx64(): ExecutableBuffer =
  var a = newAssembler(akX64)
  # lo = a*b in rax (returned), hi stored through the 3rd pointer.
  # rdx carries hiPtr in and hi out: stash the pointer in r11 first,
  # and copy src through r10 so no aliasing bites on either ABI
  # (Win64 passes arg2 in rdx, which is also the hi destination).
  # r10/r11 are caller-saved and never argument registers.
  dynasm a:
    arch x64
    alias aval, rdi, rcx
    alias bval, rsi, rdx
    alias hiptr, rdx, r8
    mov r11, hiptr
    mov rax, aval
    mov r10, bval
    mulx rdx, rax, r10
    mov [r11], rdx
    ret()
  result = a.finalize()

type MulxFn* = proc(a, b: uint64, hiPtr: pointer): uint64 {.cdecl, gcsafe.}

var gMulxLock: Lock
initLock(gMulxLock) # module init runs single-threaded at startup
var gMulxBuf: ExecutableBuffer
var gMulxReady: Atomic[bool]
var gMulxWorks = -1 # -1 unknown, 0 broken, 1 works (functional gate)

proc ensureMulxJit() =
  if gMulxReady.load(moAcquire):
    return
  withLock(gMulxLock):
    if gMulxReady.load(moRelaxed):
      return
    gMulxBuf = assembleMulx64()
    gMulxReady.store(true, moRelease)

proc mulwideJitAvailable*(): bool =
  ## True once the kernel assembles AND executes correctly (2*3 == 6).
  ## False on W^X-hardened targets and on hosts whose MULX data flow is
  ## wrong (verified against clang asm on one such box); callers fall
  ## back to portable splitting.
  if gMulxWorks >= 0:
    return gMulxWorks == 1
  try:
    ensureMulxJit()
  except CatchableError:
    gMulxWorks = 0
    return false
  let f = cast[MulxFn](gMulxBuf.ptrAt(AssemblyOffset(0)))
  var hi = 0xAAAAAAAAAAAAAAAA'u64
  let lo = f(2, 3, addr hi)
  # lo must be 6 and hi 0; on the broken host lo is lo_in*rdx_garbage.
  let ok = lo == 6 and hi == 0
  gMulxWorks = if ok: 1 else: 0
  ok

proc mulWideJit*(a, b: uint64, hi: var uint64): uint64 =
  ## lo = a*b mod 2^64, hi = floor(a*b / 2^64). Check
  ## mulwideJitAvailable() first on constrained targets.
  ensureMulxJit()
  let f = cast[MulxFn](gMulxBuf.ptrAt(AssemblyOffset(0)))
  f(a, b, addr hi)
