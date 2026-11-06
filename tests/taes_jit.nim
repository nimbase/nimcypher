import std/unittest
import std/random

import nimcypher/algos/aes
import nimcypher/algos/internal/aes_jit
import nimcypher/algos/common

# Differential: JIT batched kernels vs scalar reference. Runs with
# -d:features.nimcypher.nimdynasm on amd64.

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
