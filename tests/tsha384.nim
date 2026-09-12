# Tests for SHA-384 and HMAC-SHA-384 (FIPS 180-4, RFC 4231).
import std/strutils
import std/unittest

import nimcypher/hash
import nimcypher/utils

proc lhex(d: openArray[byte]): string = toHex(d).toLowerAscii

suite "sha384":
  test "empty string (FIPS 180-4)":
    check lhex(sha384("")) ==
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e" &
      "1da274edebfe76f65fbd51ad2f14898b95b"

  test "\"abc\" (FIPS 180-4)":
    check lhex(sha384("abc")) ==
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff" &
      "5bed8086072ba1e7cc2358baeca134c825a7"

  test "streaming matches one-shot":
    var st = initSha384()
    st.update("a")
    st.update("bc")
    check lhex(finish(st)) == lhex(sha384("abc"))

  test "HMAC-SHA-384 RFC 4231 test case 1":
    var k = newSeq[byte](20)
    for i in 0 ..< 20: k[i] = 0x0b
    check lhex(sha384Hmac(k, toBytes("Hi There"))) ==
      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7ceb" &
      "c59cfaea9ea9076ede7f4af152e8b2fa9cb6"

  test "HMAC streaming matches one-shot":
    var st = initSha384Hmac(toBytes("key"))
    st.update(toBytes("The quick brown fox "))
    st.update(toBytes("jumps over the lazy dog"))
    check lhex(finish(st)) ==
      lhex(sha384Hmac(toBytes("key"),
        toBytes("The quick brown fox jumps over the lazy dog")))
