import std/unittest
import std/options

import nimcypher/algos/gcm

import vectorutils

# NIST GCM test vectors (gcmRef: "The Galois/Counter Mode of Operation",
# GCM-AES128/GCM-AES256 example sets, 128-bit tags).
const nistK128 = "feffe9928665731c6d6a8f9467308308"
const nistK256 = nistK128 & "feffe9928665731c6d6a8f9467308308"
const nistIv = "cafebabefacedbaddecaf888"

const nistPt64 = "d9313225f88406e5a55909c5aff5269a" &
                 "86a7a9531534f7da2e4c303d8a318a72" &
                 "1c3c0c95956809532fcf0e2449a6b525" &
                 "b16aedf5aa0de657ba637b391aafd255"
const nistAad64 = "3ad77bb40d7a3660a89ecaf32466ef97" &
                  "f5d3d58503b9699de785895a96fdbaaf" &
                  "43b1cd7f598ece23881b00e3ed030688" &
                  "7b0c785e27e8ad3f8223207104725dd4"
const nistCt128 = "42831ec2217774244b7221b784d0d49c" &
                  "e3aa212f2c02a4e035c17e2329aca12e" &
                  "21d514b25466931c7d8f6a5aac84aa05" &
                  "1ba30b396a0aac973d58e091473f5985"
const nistCt256 = "522dc1f099567d07f47f37a32a84427d" &
                  "643a8cdcbfe5c0c97598a2bd2555d1aa" &
                  "8cb08e48590dbb3da7b08b1056828838" &
                  "c5f61e6393ba7a0abcc9f662898015ad"
const nistPt60 = nistPt64[0 ..< 120]
const nistAad20 = nistAad64[0 ..< 40]
const nistCt60 = nistCt128[0 ..< 120]

suite "NIST GCM-AES128 examples":
  const key = toArray[16](hexToBytes(nistK128))
  const iv = toArray[12](hexToBytes(nistIv))

  test "example 1: empty plaintext and AAD":
    let (ct, tag) = gcmLock(key, iv, @[], @[])
    check ct.len == 0
    check @tag == hexToBytes("3247184b3c4f69a44dbcd22887bbb418")

  test "example 2: 512-bit plaintext":
    let pt = hexToBytes(nistPt64)
    let (ct, tag) = gcmLock(key, iv, pt, @[])
    check ct == hexToBytes(nistCt128)
    check @tag == hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4")
    check gcmUnlock(key, iv, ct, tag) == some(pt)

  test "example 3: 512-bit AAD only":
    let (_, tag) = gcmLock(key, iv, @[], hexToBytes(nistAad64))
    check @tag == hexToBytes("5f91d77123ef5eb9997913849b8dc1e9")

  test "example 4: plaintext and AAD":
    let pt = hexToBytes(nistPt64)
    let ad = hexToBytes(nistAad64)
    let (ct, tag) = gcmLock(key, iv, pt, ad)
    check ct == hexToBytes(nistCt128)
    check @tag == hexToBytes("64c0232904af398a5b67c10b53a5024d")
    check gcmUnlock(key, iv, ct, tag, ad) == some(pt)

  test "example 5: partial final blocks":
    let pt = hexToBytes(nistPt60)
    let ad = hexToBytes(nistAad20)
    let (ct, tag) = gcmLock(key, iv, pt, ad)
    check ct == hexToBytes(nistCt60)
    check @tag == hexToBytes("f07c2528eea2fca1211f905e1b6a881b")
    check gcmUnlock(key, iv, ct, tag, ad) == some(pt)

suite "NIST GCM-AES256 examples":
  const key = toArray[32](hexToBytes(nistK256))
  const iv = toArray[12](hexToBytes(nistIv))

  test "example 1: empty plaintext and AAD":
    let (_, tag) = gcmLock(key, iv, @[], @[])
    check @tag == hexToBytes("fd2caa16a5832e76aa132c1453eeda7e")

  test "example 2: 512-bit plaintext":
    let pt = hexToBytes(nistPt64)
    let (ct, tag) = gcmLock(key, iv, pt, @[])
    check ct == hexToBytes(nistCt256)
    check @tag == hexToBytes("b094dac5d93471bdec1a502270e3cc6c")
    check gcmUnlock(key, iv, ct, tag) == some(pt)

  test "example 3: 512-bit AAD only":
    let (_, tag) = gcmLock(key, iv, @[], hexToBytes(nistAad64))
    check @tag == hexToBytes("de34b6dcd4cee2fdbec3cea01af1ee44")

  test "example 4: plaintext and AAD":
    let pt = hexToBytes(nistPt64)
    let ad = hexToBytes(nistAad64)
    let (ct, tag) = gcmLock(key, iv, pt, ad)
    check ct == hexToBytes(nistCt256)
    check @tag == hexToBytes("c06d76f31930fef37acae23ed465ae62")
    check gcmUnlock(key, iv, ct, tag, ad) == some(pt)

  test "example 5: partial final blocks":
    let pt = hexToBytes(nistPt60)
    let ad = hexToBytes(nistAad20)
    let (ct, tag) = gcmLock(key, iv, pt, ad)
    check ct == hexToBytes(nistCt256[0 ..< 120])
    check @tag == hexToBytes("e097195f4532da895fb917a5a55c6aa0")
    check gcmUnlock(key, iv, ct, tag, ad) == some(pt)

suite "non-96-bit IV derivation":
  test "long IV round-trips and differs from truncated IV":
    let key = toArray[16](hexToBytes(nistK128))
    let longIv = hexToBytes("cafebabefacedbaddecaf88811223344556677889900aabb")
    let msg = hexToBytes(nistPt64)
    let (ct, tag) = gcmLock(key, longIv, msg, @[])
    check gcmUnlock(key, longIv, ct, tag) == some(msg)
    # a different IV must produce a different tag
    let otherIv = hexToBytes("cafebabefacedbaddecaf88811223344556677889900aacb")
    let (_, tag2) = gcmLock(key, otherIv, msg, @[])
    check tag != tag2
  test "empty IV raises":
    expect ValueError:
      discard gcmLock(toArray[16](hexToBytes(nistK128)), @[], @[], @[])

suite "streaming == one-shot":
  proc makeData(n: int): seq[byte] =
    result = newSeq[byte](n)
    for i in 0 ..< n:
      result[i] = byte(i * 29 + 3)

  test "chunked encryption matches one-shot at every boundary":
    for chunk in [1, 3, 13, 15, 16, 17, 32, 100]:
      let key = toArray[16](hexToBytes(nistK128))
      let iv = toArray[12](hexToBytes(nistIv))
      let data = makeData(77 + chunk)
      var ctx: GcmContext
      initGcm(ctx, key, iv)
      gcmAddAad(ctx, makeData(chunk))
      var acc: seq[byte]
      var off = 0
      while off < data.len:
        let take = min(chunk, data.len - off)
        acc.add(gcmEncryptUpdate(ctx, data.toOpenArray(off, off + take - 1)))
        off += take
      let tagS = gcmFinishEnc(ctx)
      let (whole, tagO) = gcmLock(key, iv, data, makeData(chunk))
      check acc == whole
      check tagS == tagO

  test "chunked decryption verifies like one-shot":
    for chunk in [5, 16, 33]:
      let key = toArray[32](hexToBytes(nistK256))
      let iv = toArray[12](hexToBytes(nistIv))
      let data = makeData(90 + chunk)
      let (ct, tag) = gcmLock(key, iv, data, @[])
      var ctx: GcmContext
      initGcm(ctx, key, iv)
      var acc: seq[byte]
      var okSoFar = true
      var off = 0
      while off < ct.len:
        let take = min(chunk, ct.len - off)
        acc.add(gcmDecryptUpdate(ctx, ct.toOpenArray(off, off + take - 1)))
        off += take
      okSoFar = gcmFinishDec(ctx, tag)
      check okSoFar
      check acc == data

suite "tamper rejection":
  const key = toArray[16](hexToBytes(nistK128))
  const iv = toArray[12](hexToBytes(nistIv))

  test "flipped ciphertext bit rejected":
    let msg = hexToBytes(nistPt64)
    var (ct, tag) = gcmLock(key, iv, msg, @[])
    ct[10] = ct[10] xor byte(1)
    check gcmUnlock(key, iv, ct, tag).isNone
  test "flipped tag byte rejected":
    let msg = hexToBytes(nistPt64)
    var (ct, tag) = gcmLock(key, iv, msg, @[])
    tag[0] = tag[0] xor byte(0x80)
    check gcmUnlock(key, iv, ct, tag).isNone
  test "flipped AAD byte rejected":
    let msg = hexToBytes(nistPt64)
    let ad = hexToBytes(nistAad20)
    let (ct, tag) = gcmLock(key, iv, msg, ad)
    var badAd = ad
    badAd[3] = badAd[3] xor byte(2)
    check gcmUnlock(key, iv, ct, tag, badAd).isNone
  test "finishDec fails without releasing trust":
    let msg = hexToBytes(nistPt64)
    var (ct, tag) = gcmLock(key, iv, msg, @[])
    tag[15] = tag[15] xor byte(1)
    var ctx: GcmContext
    initGcm(ctx, key, iv)
    discard gcmDecryptUpdate(ctx, ct)
    check gcmFinishDec(ctx, tag) == false

suite "truncated tags":
  const key = toArray[16](hexToBytes(nistK128))
  const iv = toArray[12](hexToBytes(nistIv))

  test "12-byte tag prefix verifies":
    let msg = hexToBytes(nistPt60)
    let (ct, tag) = gcmLock(key, iv, msg, @[])
    check gcmUnlock(key, iv, ct, tag[0 ..< 12]).isSome
  test "corrupted short tag rejected":
    let msg = hexToBytes(nistPt60)
    let (ct, tag) = gcmLock(key, iv, msg, @[])
    var bad = tag[0 ..< 12]
    bad[11] = bad[11] xor byte(1)
    check gcmUnlock(key, iv, ct, bad).isNone
  test "empty tag rejected":
    let msg = hexToBytes(nistPt60)
    let (ct, _) = gcmLock(key, iv, msg, @[])
    check gcmUnlock(key, iv, ct, @[]).isNone

suite "input validation":
  test "bad key length raises":
    expect ValueError:
      var ctx: GcmContext
      initGcm(ctx, newSeq[byte](15), toArray[12](hexToBytes(nistIv)))
  test "AAD after data raises":
    var ctx: GcmContext
    initGcm(ctx, toArray[16](hexToBytes(nistK128)),
            toArray[12](hexToBytes(nistIv)))
    discard gcmEncryptUpdate(ctx, @[byte 1])
    expect ValueError:
      gcmAddAad(ctx, @[byte 2])
