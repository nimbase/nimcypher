import std/unittest

import nimcypher/algos/aes

import vectorutils

func toHex(a: array[16, byte]): string =
  result = newStringOfCap(32)
  for b in a:
    let hi = int(b) shr 4
    let lo = int(b) and 15
    result.add(chr(if hi < 10: ord('0') + hi else: ord('a') + hi - 10))
    result.add(chr(if lo < 10: ord('0') + lo else: ord('a') + lo - 10))

func toSeqBytes(s: string): seq[byte] =
  hexToBytes(s)

# FIPS-197 Appendix C
const fips197Key128 = "000102030405060708090a0b0c0d0e0f"
const fips197Key192 = fips197Key128 & "1011121314151617"
const fips197Key256 = fips197Key192 & "18191a1b1c1d1e1f"
const fips197Pt = "00112233445566778899aabbccddeeff"

# NIST SP 800-38A appendix F. The plaintext is shared by ECB/CBC/CFB/OFB;
# CTR uses its own initial counter block.
const sp38aPt = "6bc1bee22e409f96e93d7e117393172a" &
                "ae2d8a571e03ac9c9eb76fac45af8e51" &
                "30c81c46a35ce411e5fbc1191a0a52ef" &
                "f69f2445df4f9b17ad2b417be66c3710"
const sp38aIv = "000102030405060708090a0b0c0d0e0f"
const sp38aCtr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

proc suiteVectors(keyLen: int) =
  let keyHex = case keyLen
               of 128: "2b7e151628aed2a6abf7158809cf4f3c"
               of 192: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
               else: "603deb1015ca71be2b73aef0857d7781" &
                     "1f352c073b6108d72d9810a30914dff4"
  let ecbCt = case keyLen
              of 128: "3ad77bb40d7a3660a89ecaf32466ef97" &
                      "f5d3d58503b9699de785895a96fdbaaf" &
                      "43b1cd7f598ece23881b00e3ed030688" &
                      "7b0c785e27e8ad3f8223207104725dd4"
              of 192: "bd334f1d6e45f25ff712a214571fa5cc" &
                      "974104846d0ad3ad7734ecb3ecee4eef" &
                      "ef7afd2270e2e60adce0ba2face6444e" &
                      "9a4b41ba738d6c72fb16691603c18e0e"
              else: "f3eed1bdb5d2a03c064b5a7e3db181f8" &
                    "591ccb10d410ed26dc5ba74a31362870" &
                    "b6ed21b99ca6f4f9f153e7b1beafed1d" &
                    "23304b7a39f9f3ff067d8d8f9e24ecc7"
  let cbcCt = case keyLen
              of 128: "7649abac8119b246cee98e9b12e9197d" &
                      "5086cb9b507219ee95db113a917678b2" &
                      "73bed6b8e3c1743b7116e69e22229516" &
                      "3ff1caa1681fac09120eca307586e1a7"
              of 192: "4f021db243bc633d7178183a9fa071e8" &
                      "b4d9ada9ad7dedf4e5e738763f69145a" &
                      "571b242012fb7ae07fa9baac3df102e0" &
                      "08b0e27988598881d920a9e64f5615cd"
              else: "f58c4c04d6e5f1ba779eabfb5f7bfbd6" &
                    "9cfc4e967edb808d679f777bc6702c7d" &
                    "39f23369a9d9bacfa530e26304231461" &
                    "b2eb05e2c39be9fcda6c19078c6a9d1b"
  let cfbCt = case keyLen
              of 128: "3b3fd92eb72dad20333449f8e83cfb4a" &
                      "c8a64537a0b3a93fcde3cdad9f1ce58b" &
                      "26751f67a3cbb140b1808cf187a4f4df" &
                      "c04b05357c5d1c0eeac4c66f9ff7f2e6"
              of 192: "cdc80d6fddf18cab34c25909c99a4174" &
                      "67ce7f7f81173621961a2b70171d3d7a" &
                      "2e1e8a1dd59b88b1c8e60fed1efac4c9" &
                      "c05f9f9ca9834fa042ae8fba584b09ff"
              else: "dc7e84bfda79164b7ecd8486985d3860" &
                    "39ffed143b28b1c832113c6331e5407b" &
                    "df10132415e54b92a13ed0a8267ae2f9" &
                    "75a385741ab9cef82031623d55b1e471"
  let ofbCt = case keyLen
              of 128: "3b3fd92eb72dad20333449f8e83cfb4a" &
                      "7789508d16918f03f53c52dac54ed825" &
                      "9740051e9c5fecf64344f7a82260edcc" &
                      "304c6528f659c77866a510d9c1d6ae5e"
              of 192: "cdc80d6fddf18cab34c25909c99a4174" &
                      "fcc28b8d4c63837c09e81700c1100401" &
                      "8d9a9aeac0f6596f559c6d4daf59a5f2" &
                      "6d9f200857ca6c3e9cac524bd9acc92a"
              else: "dc7e84bfda79164b7ecd8486985d3860" &
                    "4febdc6740d20b3ac88f6ad82a4fb08d" &
                    "71ab47a086e86eedf39d1c5bba97c408" &
                    "0126141d67f37be8538f5a8be740e484"
  let ctrCt = case keyLen
              of 128: "874d6191b620e3261bef6864990db6ce" &
                      "9806f66b7970fdff8617187bb9fffdff" &
                      "5ae4df3edbd5d35e5b4f09020db03eab" &
                      "1e031dda2fbe03d1792170a0f3009cee"
              of 192: "1abc932417521ca24f2b0459fe7e6e0b" &
                      "090339ec0aa6faefd5ccc2c6f4ce8e94" &
                      "1e36b26bd1ebc670d1bd1d665620abf7" &
                      "4f78a7f6d29809585a97daec58c6b050"
              else: "601ec313775789a5b7a7f504bbf3d228" &
                    "f443e3ca4d62b59aca84e990cacaf5c5" &
                    "2b0930daa23de94ce87017ba2d84988d" &
                    "dfc9c58db67aada613c2dd08457941a6"

  let key = hexToBytes(keyHex)
  let pt = hexToBytes(sp38aPt)
  var ctx = initAes(key)

  test "SP 800-38A ECB-AES" & $keyLen & " encrypt":
    check ecbEncrypt(ctx, pt) == hexToBytes(ecbCt)
  test "SP 800-38A ECB-AES" & $keyLen & " decrypt":
    check ecbDecrypt(ctx, hexToBytes(ecbCt)) == pt
  test "SP 800-38A CBC-AES" & $keyLen & " encrypt":
    check cbcEncryptOne(ctx, toArray[16](hexToBytes(sp38aIv)), pt) ==
      hexToBytes(cbcCt)
  test "SP 800-38A CBC-AES" & $keyLen & " decrypt":
    check cbcDecryptOne(ctx, toArray[16](hexToBytes(sp38aIv)),
                        hexToBytes(cbcCt)) == pt
  test "SP 800-38A CFB128-AES" & $keyLen & " encrypt":
    check cfbEncryptOne(ctx, toArray[16](hexToBytes(sp38aIv)), pt) ==
      hexToBytes(cfbCt)
  test "SP 800-38A CFB128-AES" & $keyLen & " decrypt":
    check cfbDecryptOne(ctx, toArray[16](hexToBytes(sp38aIv)),
                        hexToBytes(cfbCt)) == pt
  test "SP 800-38A OFB-AES" & $keyLen & " encrypt":
    check ofbCryptOne(ctx, toArray[16](hexToBytes(sp38aIv)), pt) ==
      hexToBytes(ofbCt)
  test "SP 800-38A OFB-AES" & $keyLen & " decrypt":
    check ofbCryptOne(ctx, toArray[16](hexToBytes(sp38aIv)),
                      hexToBytes(ofbCt)) == pt
  test "SP 800-38A CTR-AES" & $keyLen & " encrypt":
    check ctrCryptOne(ctx, toArray[16](hexToBytes(sp38aCtr)), pt) ==
      hexToBytes(ctrCt)
  test "SP 800-38A CTR-AES" & $keyLen & " decrypt":
    check ctrCryptOne(ctx, toArray[16](hexToBytes(sp38aCtr)),
                      hexToBytes(ctrCt)) == pt

suite "FIPS-197 block vectors":
  test "AES-128 Appendix C.1":
    let ctx = initAes(hexToBytes(fips197Key128))
    var dst: array[16, byte]
    encryptBlock(ctx, dst, toArray[16](hexToBytes(fips197Pt)))
    check dst.toHex == "69c4e0d86a7b0430d8cdb78070b4c55a"
    decryptBlock(ctx, dst,
      toArray[16](hexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a")))
    check dst == toArray[16](hexToBytes(fips197Pt))
  test "AES-192 Appendix C.2":
    let ctx = initAes(hexToBytes(fips197Key192))
    var dst: array[16, byte]
    encryptBlock(ctx, dst, toArray[16](hexToBytes(fips197Pt)))
    check dst.toHex == "dda97ca4864cdfe06eaf70a0ec0d7191"
    decryptBlock(ctx, dst,
      toArray[16](hexToBytes("dda97ca4864cdfe06eaf70a0ec0d7191")))
    check dst == toArray[16](hexToBytes(fips197Pt))
  test "AES-256 Appendix C.3":
    let ctx = initAes(hexToBytes(fips197Key256))
    var dst: array[16, byte]
    encryptBlock(ctx, dst, toArray[16](hexToBytes(fips197Pt)))
    check dst.toHex == "8ea2b7ca516745bfeafc49904b496089"
    decryptBlock(ctx, dst,
      toArray[16](hexToBytes("8ea2b7ca516745bfeafc49904b496089")))
    check dst == toArray[16](hexToBytes(fips197Pt))

suite "SP 800-38A mode vectors":
  suiteVectors(128)
  suiteVectors(192)
  suiteVectors(256)

suite "streaming == one-shot":
  proc makeData(n: int): seq[byte] =
    result = newSeq[byte](n)
    for i in 0 ..< n:
      result[i] = byte(i * 31 + 7)

  const chunks = [1, 3, 7, 15, 16, 17, 31, 64]

  test "ctr stream matches one-shot at every chunk size":
    for chunk in chunks:
      let data = makeData(100 + chunk)
      var s: AesCtrStream
      initAesCtr(s, hexToBytes(fips197Key128), toArray[16](hexToBytes(sp38aCtr)))
      var acc: seq[byte]
      var off = 0
      while off < data.len:
        let take = min(chunk, data.len - off)
        acc.add(aesCtrUpdate(s, data.toOpenArray(off, off + take - 1)))
        off += take
      let whole = ctrCryptOne(initAes(hexToBytes(fips197Key128)),
                              toArray[16](hexToBytes(sp38aCtr)), data)
      check acc == whole

  test "ofb stream matches one-shot at every chunk size":
    for chunk in chunks:
      let data = makeData(100 + chunk)
      var s: AesOfbStream
      initAesOfb(s, hexToBytes(fips197Key128), toArray[16](hexToBytes(sp38aIv)))
      var acc: seq[byte]
      var off = 0
      while off < data.len:
        let take = min(chunk, data.len - off)
        acc.add(aesOfbUpdate(s, data.toOpenArray(off, off + take - 1)))
        off += take
      let whole = ofbCryptOne(initAes(hexToBytes(fips197Key128)),
                              toArray[16](hexToBytes(sp38aIv)), data)
      check acc == whole

  test "cfb stream matches one-shot (encrypt and decrypt)":
    for chunk in chunks:
      let data = makeData(100 + chunk)
      var se: AesCfbEncStream
      initAesCfbEnc(se, hexToBytes(fips197Key128),
                    toArray[16](hexToBytes(sp38aIv)))
      var ct: seq[byte]
      var off = 0
      while off < data.len:
        let take = min(chunk, data.len - off)
        ct.add(aesCfbEncryptUpdate(se, data.toOpenArray(off, off + take - 1)))
        off += take
      let whole = cfbEncryptOne(initAes(hexToBytes(fips197Key128)),
                                toArray[16](hexToBytes(sp38aIv)), data)
      check ct == whole
      var sd: AesCfbDecStream
      initAesCfbDec(sd, hexToBytes(fips197Key128),
                    toArray[16](hexToBytes(sp38aIv)))
      var back: seq[byte]
      off = 0
      while off < ct.len:
        let take = min(chunk, ct.len - off)
        back.add(aesCfbDecryptUpdate(sd, ct.toOpenArray(off, off + take - 1)))
        off += take
      check back == data

suite "PKCS#7 padding":
  test "pads and unpads":
    check pkcs7Pad(@[]).len == 16
    check pkcs7Pad(newSeq[byte](15)).len == 16
    check pkcs7Pad(newSeq[byte](16)).len == 32
    let data = (@[byte 1, 2, 3] & newSeq[byte](10))
    check pkcs7Unpad(pkcs7Pad(data)) == data
  test "padding bytes are correct":
    let padded = pkcs7Pad(newSeq[byte](13))
    check padded.len == 16
    var ok = true
    for i in 13 ..< 16:
      ok = ok and padded[i] == byte(3)
    check ok
  test "invalid padding raises":
    var bad = newSeq[byte](16)
    bad[15] = byte(17)
    expect ValueError:
      discard pkcs7Unpad(bad)
    var bad2 = newSeq[byte](16)
    bad2[15] = byte(3)
    expect ValueError:
      discard pkcs7Unpad(bad2)

suite "input validation":
  test "bad key lengths raise":
    expect ValueError:
      discard initAes(newSeq[byte](15))
    expect ValueError:
      discard initAes(newSeq[byte](17))
    expect ValueError:
      discard initAes(newSeq[byte](0))
  test "unaligned ECB/CBC input raises":
    let ctx = initAes(hexToBytes(fips197Key128))
    expect ValueError:
      discard ecbEncrypt(ctx, newSeq[byte](17))
    expect ValueError:
      discard cbcEncryptOne(ctx, default(array[16, byte]), newSeq[byte](1))
