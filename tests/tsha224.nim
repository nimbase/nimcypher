import std/unittest

import nimcypher/algos/sha256 as sha256Algo
import nimcypher/algos/sha224 as sha224Algo
import nimcypher/hash as hashApi
import vectorutils

proc hex(s: string): seq[byte] = hexToBytes(s)

test "sha224 FIPS 180-4 vectors":
  check sha224Algo.sha224(@[]) == hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
  check sha224Algo.sha224(hex("616263")) == hex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
  var msg3: seq[byte]
  for c in "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
    msg3.add byte(c)
  check sha224Algo.sha224(msg3) == hex("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")

test "sha224 one million a":
  var msg = newSeq[byte](1_000_000)
  for i in 0 ..< msg.len:
    msg[i] = byte('a')
  check sha224Algo.sha224(msg) == hex("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")

test "sha224 incremental == one-shot incl split inside pad":
  var input: seq[byte]
  for j in 0 ..< 200:
    input.add(byte(j * 3))
  let whole = sha224Algo.sha224(input)
  var ctx: sha256Algo.Sha256Context
  sha224Algo.init224(ctx)
  sha256Algo.update(ctx, input[0 ..< 55])
  sha256Algo.update(ctx, input[55 ..< 64])
  sha256Algo.update(ctx, input[64 ..^ 1])
  let chunked = sha256Algo.final(ctx)
  for i in 0 ..< 28:
    check chunked[i] == whole[i]
  # single-byte chunks
  var c2: sha256Algo.Sha256Context
  sha224Algo.init224(c2)
  for b in input:
    sha256Algo.update(c2, [b])
  let single = sha256Algo.final(c2)
  for i in 0 ..< 28:
    check single[i] == whole[i]

test "hmac-sha224 RFC 4231 one-shot":
  check sha224Algo.sha224Hmac(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                 hex("4869205468657265")) ==
        hex("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")
  check sha224Algo.sha224Hmac(hex("4a656665"),
                 hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")) ==
        hex("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44")
  var k3 = newSeq[byte](20)
  for i in 0 ..< 20: k3[i] = 0xaa
  var d3 = newSeq[byte](50)
  for i in 0 ..< 50: d3[i] = 0xdd
  check sha224Algo.sha224Hmac(k3, d3) == hex("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea")
  check sha224Algo.sha224Hmac(hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                 hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")) ==
        hex("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a")

test "hmac-sha224 long key (> block) RFC 4231 cases 6-7":
  var k6 = newSeq[byte](131)
  for i in 0 ..< 131: k6[i] = 0xaa
  let d6 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
  check sha224Algo.sha224Hmac(k6, d6) == hex("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e")
  let d7 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461")
  check sha224Algo.sha224Hmac(k6, d7) == hex("61d14dfa6c5fcc810c15496a410dbf389ccefe02a9694ebde98fd747")

test "hmac incremental == one-shot":
  var key: seq[byte]
  for j in 0 ..< 32:
    key.add(byte(j + 1))
  var input: seq[byte]
  for j in 0 ..< 100:
    input.add(byte(j * 5))
  let whole = sha224Algo.sha224Hmac(key, input)
  var ctx: sha224Algo.Sha224HmacContext
  sha224Algo.initHmac224(ctx, key)
  sha224Algo.update(ctx, input[0 ..< 40])
  sha224Algo.update(ctx, input[40 ..^ 1])
  check sha224Algo.final(ctx) == whole

test "hmac empty key equals zero-padded key":
  let msg = hex("616263646566")
  check sha224Algo.sha224Hmac(newSeq[byte](0), msg) ==
        sha224Algo.sha224Hmac(newSeq[byte](64), msg)

test "high-level sha224 api":
  check hashApi.sha224("abc") == sha224Algo.sha224(hex("616263"))
  check hashApi.sha224Hex("abc") == "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
  check hashApi.sha224HmacHex("Jefe", "what do ya want for nothing?") == "A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E6148008FD05E44"
  var st = hashApi.initSha224()
  st.update("a")
  st.update("bc")
  check st.finish() == sha224Algo.sha224(hex("616263"))
  var hm = hashApi.initSha224Hmac("Jefe")
  hm.update("what do ya want ")
  hm.update("for nothing?")
  check hm.finish() == sha224Algo.sha224Hmac(hex("4a656665"),
    hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f"))
