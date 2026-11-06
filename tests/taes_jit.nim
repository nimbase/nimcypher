import std/unittest
import std/random

import nimcypher/algos/aes
import nimcypher/algos/common

# Differential: JIT batched kernels vs scalar reference. Runs with
# -d:features.nimcypher.nimdynasm on amd64 or arm64.


when defined(amd64) or defined(arm64):
  import nimcypher/algos/internal/aes_jit

  suite "aes jit vs scalar":
    test "encrypt/decrypt agree, all key sizes and tails":
      randomize(0xAE51)
      for keyLen in [16, 24, 32]:
        var key = newSeq[byte](keyLen)
        for i in 0 ..< keyLen:
          key[i] = byte(rand(255))
        var ctx = initAes(key)
        for nb in [1, 2, 7, 8, 9, 15, 16, 17, 24]:
          var pt = newSeq[byte](nb * 16)
          for i in 0 ..< pt.len:
            pt[i] = byte(rand(255))
          var ej, es, dj, ds: seq[byte]
          ej = newSeq[byte](nb * 16)
          es = newSeq[byte](nb * 16)
          dj = newSeq[byte](nb * 16)
          ds = newSeq[byte](nb * 16)
          encryptBlocksJit(ctx.rounds, addr ctx.nrk[0],
            cast[BytePtr](addr ej[0]), cast[BytePtr](addr pt[0]), nb)
          encryptBlocksScalar(ctx,
            cast[BytePtr](addr es[0]), cast[BytePtr](addr pt[0]), nb)
          check ej == es
          decryptBlocksJit(ctx.rounds, addr ctx.nrk[0], addr ctx.nrkInv[0],
            cast[BytePtr](addr dj[0]), cast[BytePtr](addr ej[0]), nb)
          decryptBlocksScalar(ctx,
            cast[BytePtr](addr ds[0]), cast[BytePtr](addr es[0]), nb)
          check dj == ds
          check dj == pt
        wipeAesContext(ctx)

    test "ctr crypt kernel matches buffered reference + wrap":
      randomize(0xC72)
      for keyLen in [16, 24, 32]:
        var key = newSeq[byte](keyLen)
        for i in 0 ..< keyLen:
          key[i] = byte(rand(255))
        var ctx = initAes(key)
        var ctr: array[16, byte]
        for i in 0 ..< 16:
          ctr[i] = byte(rand(255))
        var pt: array[128, byte]
        for i in 0 ..< 128:
          pt[i] = byte(rand(255))
        # reference: explicit counters, batch encrypt, xor, advance
        var cbs: array[128, byte]
        var c = ctr
        for b in 0 ..< 8:
          copyMem(addr cbs[b * 16], addr c[0], 16)
          var v = (uint32(c[12]) shl 24) or (uint32(c[13]) shl 16) or
                  (uint32(c[14]) shl 8) or uint32(c[15])
          v += 1
          c[12] = byte(v shr 24)
          c[13] = byte(v shr 16)
          c[14] = byte(v shr 8)
          c[15] = byte(v)
        var ks: array[128, byte]
        encryptBlocks(ctx, cast[BytePtr](addr ks[0]),
                      cast[BytePtr](addr cbs[0]), 8)
        var exp: array[128, byte]
        for i in 0 ..< 128:
          exp[i] = pt[i] xor ks[i]
        var got: array[128, byte]
        var kctr = ctr
        ctrCrypt8Jit(ctx.rounds, addr ctx.nrk[0],
                     cast[BytePtr](addr got[0]),
                     cast[BytePtr](addr pt[0]),
                     cast[BytePtr](addr kctr[0]))
        check got == exp
        check kctr == c
        wipeAesContext(ctx)
      # counter wrap: 0xFFFFFFFE + 8 -> 0x00000006
      var ctx2 = initAes(@[byte 0, 1, 2, 3, 4, 5, 6, 7,
                           8, 9, 10, 11, 12, 13, 14, 15])
      var wrap: array[16, byte]
      for i in 0 ..< 12:
        wrap[i] = 0xAA
      wrap[12] = 0xFF
      wrap[13] = 0xFF
      wrap[14] = 0xFF
      wrap[15] = 0xFE
      var pt2: array[128, byte]
      var got2: array[128, byte]
      ctrCrypt8Jit(ctx2.rounds, addr ctx2.nrk[0],
                   cast[BytePtr](addr got2[0]),
                   cast[BytePtr](addr pt2[0]),
                   cast[BytePtr](addr wrap[0]))
      check wrap == [0xAA'u8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                     0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                     0x00, 0x00, 0x00, 0x06]
      wipeAesContext(ctx2)

  test "arm64 crypto word goldens":
    ## Every word the arm64 backend emits, pinned against
    ## `clang --target=aarch64` (`.arch armv8-a+crypto`). Pure
    ## encoding checks: run on any host, no execution.
    check armCryptoWord(armAeseBase, 0, 1) == 0x4E284820'u32
    check armCryptoWord(armAeseBase, 5, 7) == 0x4E2848E5'u32
    check armCryptoWord(armAeseBase, 31, 30) == 0x4E284BDF'u32
    check armCryptoWord(armAesdBase, 0, 1) == 0x4E285820'u32
    check armCryptoWord(armAesdBase, 5, 7) == 0x4E2858E5'u32
    check armCryptoWord(armAesmcBase, 0, 0) == 0x4E286800'u32
    check armCryptoWord(armAesmcBase, 5, 7) == 0x4E2868E5'u32
    check armCryptoWord(armAesimcBase, 0, 0) == 0x4E287800'u32
    check armCryptoWord(armAesimcBase, 5, 7) == 0x4E2878E5'u32
    check armLdrQWord(0, 0, 0) == 0x3DC00000'u32
    check armLdrQWord(0, 2, 112) == 0x3DC01C40'u32
    check armLdrQWord(31, 0, 160) == 0x3DC0281F'u32
    check armLdrQWord(0, 31, 0) == 0x3DC003E0'u32
    check armStrQWord(1, 0, 16) == 0x3D800401'u32
    check armStrQWord(7, 1, 112) == 0x3D801C27'u32
    check armEorVWord(0, 1, 2) == 0x6E221C20'u32
    check armEorVWord(0, 0, 31) == 0x6E3F1C00'u32
else:
  suite "aes jit vs scalar (requires amd64 or arm64)":
    test "skipped elsewhere":
      skip()
