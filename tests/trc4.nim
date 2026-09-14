import std/unittest

import nimcypher/algos/rc4 as rc4Algo
import vectorutils

proc hex(s: string): seq[byte] = hexToBytes(s)

test "rc4 RFC 6229 / Wikipedia vectors":
  # key "Key", plaintext "Plaintext"
  check rc4Algo.rc4Crypt(hex("4b6579"), hex("506c61696e74657874")) ==
    hex("bbf316e8d940af0ad3")
  # key "Wiki", plaintext "pedia"
  check rc4Algo.rc4Crypt(hex("57696b69"), hex("7065646961")) ==
    hex("1021bf0420")
  # key "Secret", plaintext "Attack at dawn"
  check rc4Algo.rc4Crypt(hex("536563726574"),
    hex("41747461636b206174206461776e")) ==
    hex("45a01f645fc35b383552544b9bf5")

test "rc4 symmetry and in-place":
  let key = hex("0123456789abcdef")
  var msg: seq[byte] = @[]
  for i in 0 ..< 256:
    msg.add(byte(i))
  let enc = rc4Algo.rc4Crypt(key, msg)
  check enc != msg
  check rc4Algo.rc4Crypt(key, enc) == msg
  var buf = msg
  rc4Algo.rc4CryptInPlace(key, buf)
  check buf == enc
  rc4Algo.rc4CryptInPlace(key, buf)
  check buf == msg

test "rc4 edge cases":
  check rc4Algo.rc4Crypt(hex("aa"), @[]) == newSeq[byte](0)
  # 1-byte key still produces a keystream
  check rc4Algo.rc4Crypt(@[byte(0)], @[byte(0)]).len == 1
  # symmetry on a PDF-style 5-byte (40-bit) key
  let k40 = hex("0102030405")
  let p = hex("0011223344556677")
  check rc4Algo.rc4Crypt(k40, rc4Algo.rc4Crypt(k40, p)) == p
  expect(ValueError):
    discard rc4Algo.rc4Crypt(@[], p)
  expect(ValueError):
    discard rc4Algo.rc4Crypt(newSeq[byte](257), p)
