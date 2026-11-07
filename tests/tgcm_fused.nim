import std/unittest
import std/options
import std/random
import nimcypher/algos/gcm

when defined(features.nimcypher.nimdynasm) and defined(amd64):
  import nimcypher/algos/internal/gcm_jit
  import nimcypher/algos/aes
  import nimcypher/algos/common

# Differential: fused JIT crypt vs scalar reference and vs chunked
# streaming. Runs with -d:features.nimcypher.nimdynasm on amd64.

suite "gcm fused vs scalar":
  test "random keys/ivs/sizes/aad agree":
    randomize(0xF05E)
    for t in 0 ..< 60:
      let kl = [16, 24, 32][rand(2)]
      var key = newSeq[byte](kl)
      for i in 0 ..< kl: key[i] = byte(rand(255))
      let ivLen = [12, 12, 12, 16, 8][rand(4)]
      var iv = newSeq[byte](ivLen)
      for i in 0 ..< ivLen: iv[i] = byte(rand(255))
      let msgLen = rand(3000)
      var pt = newSeq[byte](msgLen)
      for i in 0 ..< msgLen: pt[i] = byte(rand(255))
      let adLen = rand(64)
      var ad = newSeq[byte](adLen)
      for i in 0 ..< adLen: ad[i] = byte(rand(255))
      let (c1, t1) = gcmLock(key, iv, pt, ad)
      let (cS, tS) = gcmLockScalar(key, iv, pt, ad)
      check c1 == cS
      check t1 == tS
      check gcmUnlock(key, iv, c1, t1, ad) == some(pt)
      # tamper must fail
      if c1.len > 0:
        var cb = c1
        let bi = rand(c1.len - 1)
        cb[bi] = cb[bi] xor 1
        check gcmUnlock(key, iv, cb, t1, ad).isNone

  test "chunked streaming matches one-shot":
    randomize(0x57EA)
    for t in 0 ..< 20:
      let kl = [16, 32][rand(1)]
      var key = newSeq[byte](kl)
      for i in 0 ..< kl: key[i] = byte(rand(255))
      var iv = newSeq[byte](12)
      for i in 0 ..< 12: iv[i] = byte(rand(255))
      let msgLen = 1 + rand(3000)
      var pt = newSeq[byte](msgLen)
      for i in 0 ..< msgLen: pt[i] = byte(rand(255))
      var ad = newSeq[byte](rand(32))
      for i in 0 ..< ad.len: ad[i] = byte(rand(255))
      var ctx: GcmContext
      initGcm(ctx, key, iv)
      gcmAddAad(ctx, ad)
      var parts: seq[byte] = @[]
      var off = 0
      while off < msgLen:
        let n = min(1 + rand(500), msgLen - off)
        parts.add(gcmEncryptUpdate(ctx, pt.toOpenArray(off, off + n - 1)))
        off += n
      let tag = gcmFinishEnc(ctx)
      let (whole, tagO) = gcmLock(key, iv, pt, ad)
      check parts == whole
      check tag == tagO

  test "session matches one-shot":
    randomize(0x5E55)
    for t in 0 ..< 30:
      let kl = [16, 24, 32][rand(2)]
      var key = newSeq[byte](kl)
      for i in 0 ..< kl: key[i] = byte(rand(255))
      let ivLen = [12, 12, 16, 8][rand(3)]
      var iv = newSeq[byte](ivLen)
      for i in 0 ..< ivLen: iv[i] = byte(rand(255))
      let msgLen = rand(3000)
      var pt = newSeq[byte](msgLen)
      for i in 0 ..< msgLen: pt[i] = byte(rand(255))
      var ad = newSeq[byte](rand(40))
      for i in 0 ..< ad.len: ad[i] = byte(rand(255))
      let sess = initGcmSession(key)
      let (c1, t1) = gcmLockWithSession(sess, iv, pt, ad)
      let (cS, tS) = gcmLockScalar(key, iv, pt, ad)
      check c1 == cS
      check t1 == tS
      check gcmUnlockWithSession(sess, iv, c1, t1, ad) == some(pt)
      # wrong key session must not verify
      var bad = key
      bad[0] = bad[0] xor 1
      let sessBad = initGcmSession(bad)
      check gcmUnlockWithSession(sessBad, iv, c1, t1, ad).isNone

when defined(features.nimcypher.nimdynasm) and defined(amd64):
  suite "gcm wide fused kernel":
    test "wide kernel equals four narrow calls":
      if gcmCrypt8JitAvailable():
        randomize(0x32B1)
        for _ in 0 ..< 40:
          let kl = [16, 24, 32][rand(2)]
          var key = newSeq[byte](kl)
          for i in 0 ..< kl: key[i] = byte(rand(255))
          var src = newSeq[byte](512)
          for i in 0 ..< 512: src[i] = byte(rand(255))
          var dstW = newSeq[byte](512)
          var dstN = newSeq[byte](512)
          for dec in [false, true]:
            # state = {ctr[16], acc[16], pow[8][16]}, fresh per run
            var blkW, blkN: array[288, byte] # ctr+acc+16 pow slots
            for i in 0 ..< 16:
              blkW[i] = byte(rand(255))
              blkN[i] = blkW[i]
            var actx = initAes(key)
            gcmCrypt32Jit(actx.rounds, addr actx.nrk[0],
                          cast[BytePtr](addr dstW[0]),
                          cast[BytePtr](addr src[0]),
                          cast[BytePtr](addr blkW[0]), decrypt = dec)
            for k in 0 ..< 4:
              gcmCrypt8Jit(actx.rounds, addr actx.nrk[0],
                           cast[BytePtr](addr dstN[k * 128]),
                           cast[BytePtr](addr src[k * 128]),
                           cast[BytePtr](addr blkN[0]), decrypt = dec)
            check dstW == dstN
            check blkW == blkN # ctr advanced by 32, acc folded equally
      else:
        skip()

    test "wide path matches scalar one-shot":
      var key: array[16, byte]
      var iv: array[12, byte]
      for i in 0 ..< 16: key[i] = byte i
      for i in 0 ..< 12: iv[i] = byte (i + 1)
      for msgLen in [0, 15, 16, 511, 512, 513, 1023, 1024, 1025, 2048,
                     4096, 16384, 16385]:
        var pt = newSeq[byte](msgLen)
        randomize(msgLen)
        for i in 0 ..< msgLen: pt[i] = byte(rand(255))
        let (c1, t1) = gcmLock(key, iv, pt, [])
        let (cS, tS) = gcmLockScalar(key, iv, pt, [])
        check c1 == cS
        check t1 == tS
        check gcmUnlock(key, iv, c1, t1, []) == some(pt)
