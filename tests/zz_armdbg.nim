import std/unittest
import nimcypher/algos/internal/aes_jit
import nimcypher/algos/aes
import nimcypher/algos/common
import dynasm

when defined(features.nimcypher.nimdynasm) and
    (defined(arm64) or defined(forceArmJit)):
  type KernFn = proc(nrk, dst, src: pointer) {.cdecl, gcsafe.}

  proc buildLadder(nrounds: int, finalOff: int): ExecutableBuffer =
    ## ld; eor k0; rounds 1..nrounds; eor k[finalOff]; st.
    ## nrounds = -1 -> pure ld/st identity.
    var a = newAssembler(akAarch64)
    ldStates8(a, 2, 0)
    if nrounds >= 0:
      emitAesEncRoundsA64(a, nrounds + 1)
      let d = finalOff * 16
      dynasm a:
        arch aarch64
        ldr q31, [x0, d]
      for i in 0 ..< aesJitBatch:
        a.pushU32(armEorVWord(i, i, 31))
    stStates8(a, 1, 0)
    dynasm a:
      arch aarch64
      ret()
    result = a.finalize()

  const
    keyA: array[16, byte] = [169'u8,129,192,118,146,33,225,204,17,152,205,146,7,2,121,222]
    ptA: array[16, byte] = [46'u8,146,24,235,197,208,78,22,47,183,60,27,227,53,150,244]
    expLid = [46'u8,146,24,235,197,208,78,22,47,183,60,27,227,53,150,244]
    expL0 = [135'u8,19,216,157,87,241,175,218,62,47,241,137,228,55,239,42]
    expL1 = [244'u8,151,24,209,177,166,23,17,8,140,49,109,35,212,199,242]
    expL2 = [206'u8,104,124,219,181,215,249,13,94,138,139,55,91,142,166,14]
    expL3 = [92'u8,130,149,155,124,149,94,2,114,124,70,2,0,30,160,57]
    expL4 = [180'u8,134,8,144,244,158,30,45,240,254,10,226,233,92,37,244]
    expL5 = [103'u8,121,237,75,144,5,63,131,214,134,136,132,161,17,194,32]
    expL6 = [217'u8,242,221,37,23,222,14,17,29,207,241,170,43,91,70,242]
    expL7 = [148'u8,12,56,115,105,124,49,151,38,156,91,133,96,16,133,183]
    expL8 = [52'u8,35,225,17,156,187,219,178,48,118,80,160,237,98,151,115]
    expL9 = [168'u8,75,179,240,198,27,112,190,246,34,52,150,224,133,15,26]

  suite "arm ladder":
    test "loads and stores":
      var ctx = initAes(keyA)
      var b = buildLadder(-1, 0)
      var outp: array[128, byte]
      var inp: array[128, byte]
      for i in 0 ..< 128: inp[i] = ptA[i mod 16]
      cast[KernFn](b.ptrAt(AssemblyOffset(0)))(
        addr ctx.nrk[0], addr outp[0], addr inp[0])
      check outp == inp
      b.destroy()
      wipeAesContext(ctx)
    test "prefix rounds agree":
      var ctx = initAes(keyA)
      let exps = [expL0, expL1, expL2, expL3, expL4, expL5, expL6,
                  expL7, expL8, expL9]
      for n in 0 ..< 10:
        var b = buildLadder(n, n + 1)
        var outp: array[128, byte]
        var inp: array[128, byte]
        for i in 0 ..< 128: inp[i] = ptA[i mod 16]
        cast[KernFn](b.ptrAt(AssemblyOffset(0)))(
          addr ctx.nrk[0], addr outp[0], addr inp[0])
        var ok = true
        for i in 0 ..< 128:
          if outp[i] != exps[n][i mod 16]: ok = false
        if not ok:
          echo "DIVERGE at L", n, ": got ", @outp[0 ..< 16]
        check ok
        b.destroy()
      wipeAesContext(ctx)
else:
  suite "arm ladder (inactive)":
    test "skipped":
      skip()
