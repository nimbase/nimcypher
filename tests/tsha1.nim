import std/unittest

import nimcypher/algos/sha1 as sha1Algo
import nimcypher/hash as hashApi
import vectorutils

proc hex(s: string): seq[byte] = hexToBytes(s)

test "sha1 vectors (internal)":
  # RFC 3174 / FIPS 180-4
  check sha1Algo.sha1(@[]) == hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
  check sha1Algo.sha1(hex("616263")) == hex("a9993e364706816aba3e25717850c26c9cd0d89d")
  # 56-byte second vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  var msg3: seq[byte]
  for c in "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
    msg3.add byte(c)
  check sha1Algo.sha1(msg3) == hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")

test "hmac-sha1 RFC 2202 one-shot":
  # Test case 1: key 0x0b*20, data "Hi There"
  check sha1Algo.sha1Hmac(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                 hex("4869205468657265")) ==
        hex("b617318655057264e28bc0b6fb378c8ef146be00")
  # Test case 2: key "Jefe", data "what do ya want for nothing?"
  check sha1Algo.sha1Hmac(hex("4a656665"),
                 hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")) ==
        hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
  # Test case 3: key 0xaa*20, data 0xdd*50
  var k3 = newSeq[byte](20)
  for i in 0 ..< 20: k3[i] = 0xaa
  var d3 = newSeq[byte](50)
  for i in 0 ..< 50: d3[i] = 0xdd
  check sha1Algo.sha1Hmac(k3, d3) == hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3")
  # Test case 4: key 0x01..0x19 (25 bytes), data 0xcd*50
  check sha1Algo.sha1Hmac(hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                 hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")) ==
        hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
  # Test case 6: key 0xaa*80 (> block), data "Test Using Larger Than Block-Size Key - Hash Key First"
  var k6 = newSeq[byte](80)
  for i in 0 ..< 80: k6[i] = 0xaa
  let d6 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
  check sha1Algo.sha1Hmac(k6, d6) == hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
  # Test case 7: same long key, larger data
  let d7 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461")
  check sha1Algo.sha1Hmac(k6, d7) == hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")

test "hmac-sha1 empty key equals zero-padded key":
  let msg = hex("616263646566")
  let empty = sha1Algo.sha1Hmac(newSeq[byte](0), msg)
  var zero64 = newSeq[byte](64)
  let zeroed = sha1Algo.sha1Hmac(zero64, msg)
  check empty == zeroed

test "hmac-sha1 high-level api":
  let h1 = hashApi.sha1Hmac("Jefe", "what do ya want for nothing?")
  let h2 = sha1Algo.sha1Hmac(hex("4a656665"), hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f"))
  check h1 == h2
  check hashApi.sha1HmacHex("Jefe", "what do ya want for nothing?") == "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79"
  # bytes vs string overload consistency
  check hashApi.sha1Hmac(@[byte('J'), byte('e'), byte('f'), byte('e')], @[byte('h'), byte('i')]).len == 20
  # verifyDigest
  check hashApi.verifyDigest(h1, h2)
  var bad = h1
  bad[0] = bad[0] xor 1
  check not hashApi.verifyDigest(h1, bad)
