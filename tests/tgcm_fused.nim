import std/unittest
import std/options
import std/random
import nimcypher/algos/gcm

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
