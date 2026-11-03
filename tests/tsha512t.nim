# Tests for SHA-512/224 and SHA-512/256 (FIPS 180-4) and their HMACs.
import std/strutils
import std/unittest

import nimcypher/hash as hashApi
import nimcypher/algos/sha512 as sha512Algo
import nimcypher/algos/sha512_224 as sha512_224Algo
import nimcypher/algos/sha512_256 as sha512_256Algo
import nimcypher/utils
import vectorutils

proc lhex(d: openArray[byte]): string = toHex(d).toLowerAscii

suite "sha512_224":
  test "empty string (NIST)":
    check lhex(hashApi.sha512_224("")) ==
      "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"

  test "\"abc\" (NIST)":
    check lhex(hashApi.sha512_224("abc")) ==
      "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"

  test "448-bit message (openssl oracle)":
    check lhex(hashApi.sha512_224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
      "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"

  test "streaming matches one-shot incl split inside pad":
    var input: seq[byte]
    for j in 0 ..< 200:
      input.add(byte(j * 3))
    let whole = sha512_224Algo.sha512_224(input)
    var ctx: sha512Algo.Sha512Context
    sha512_224Algo.init512_224(ctx)
    sha512Algo.update(ctx, input[0 ..< 111])
    sha512Algo.update(ctx, input[111 ..< 128])
    sha512Algo.update(ctx, input[128 ..^ 1])
    let chunked = sha512Algo.final(ctx)
    for i in 0 ..< 28:
      check chunked[i] == whole[i]
    var st = hashApi.initSha512_224()
    st.update(input[0 ..< 64])
    st.update(input[64 ..^ 1])
    check lhex(finish(st)) == lhex(whole)

  test "HMAC-SHA-512/224 (openssl oracle)":
    # key 0x0b*20, data "Hi There"
    check lhex(hashApi.sha512_224Hmac(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        toBytes("Hi There"))) ==
      "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039"
    # key "Jefe"
    check lhex(hashApi.sha512_224Hmac("Jefe", "what do ya want for nothing?")) ==
      "4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde"
    # key 0xaa*20, data 0xdd*50
    var k3 = newSeq[byte](20)
    for i in 0 ..< 20: k3[i] = 0xaa
    var d3 = newSeq[byte](50)
    for i in 0 ..< 50: d3[i] = 0xdd
    check lhex(hashApi.sha512_224Hmac(k3, d3)) ==
      "db34ea525c2c216ee5a6ccb6608bea870bbef12fd9b96a5109e2b6fc"

  test "HMAC streaming matches one-shot":
    var st = hashApi.initSha512_224Hmac(toBytes("key"))
    st.update(toBytes("The quick brown fox "))
    st.update(toBytes("jumps over the lazy dog"))
    check lhex(finish(st)) ==
      lhex(hashApi.sha512_224Hmac(toBytes("key"),
        toBytes("The quick brown fox jumps over the lazy dog")))

  test "HMAC long key (> block)":
    var k = newSeq[byte](150)
    for i in 0 ..< 150: k[i] = 0xaa
    var input: seq[byte]
    for j in 0 ..< 80: input.add(byte(j))
    var ctx: sha512_224Algo.Sha512_224HmacContext
    sha512_224Algo.initHmac512_224(ctx, k)
    sha512_224Algo.update(ctx, input[0 ..< 30])
    sha512_224Algo.update(ctx, input[30 ..^ 1])
    check sha512_224Algo.final(ctx) == sha512_224Algo.sha512_224Hmac(k, input)

suite "sha512_256":
  test "empty string (NIST)":
    check lhex(hashApi.sha512_256("")) ==
      "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"

  test "\"abc\" (NIST)":
    check lhex(hashApi.sha512_256("abc")) ==
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"

  test "448-bit message (openssl oracle)":
    check lhex(hashApi.sha512_256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
      "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"

  test "streaming matches one-shot incl split inside pad":
    var input: seq[byte]
    for j in 0 ..< 200:
      input.add(byte(j * 3))
    let whole = sha512_256Algo.sha512_256(input)
    var ctx: sha512Algo.Sha512Context
    sha512_256Algo.init512_256(ctx)
    sha512Algo.update(ctx, input[0 ..< 111])
    sha512Algo.update(ctx, input[111 ..< 128])
    sha512Algo.update(ctx, input[128 ..^ 1])
    let chunked = sha512Algo.final(ctx)
    for i in 0 ..< 32:
      check chunked[i] == whole[i]
    var st = hashApi.initSha512_256()
    st.update(input[0 ..< 64])
    st.update(input[64 ..^ 1])
    check lhex(finish(st)) == lhex(whole)

  test "HMAC-SHA-512/256 (openssl oracle)":
    check lhex(hashApi.sha512_256Hmac(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        toBytes("Hi There"))) ==
      "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab"
    check lhex(hashApi.sha512_256Hmac("Jefe", "what do ya want for nothing?")) ==
      "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"
    var k3 = newSeq[byte](20)
    for i in 0 ..< 20: k3[i] = 0xaa
    var d3 = newSeq[byte](50)
    for i in 0 ..< 50: d3[i] = 0xdd
    check lhex(hashApi.sha512_256Hmac(k3, d3)) ==
      "229006391d66c8ecddf43ba5cf8f83530ef221a4e9401840d1bead5137c8a2ea"

  test "HMAC streaming matches one-shot":
    var st = hashApi.initSha512_256Hmac(toBytes("key"))
    st.update(toBytes("The quick brown fox "))
    st.update(toBytes("jumps over the lazy dog"))
    check lhex(finish(st)) ==
      lhex(hashApi.sha512_256Hmac(toBytes("key"),
        toBytes("The quick brown fox jumps over the lazy dog")))

  test "HMAC long key (> block)":
    var k = newSeq[byte](150)
    for i in 0 ..< 150: k[i] = 0xaa
    var input: seq[byte]
    for j in 0 ..< 80: input.add(byte(j))
    var ctx: sha512_256Algo.Sha512_256HmacContext
    sha512_256Algo.initHmac512_256(ctx, k)
    sha512_256Algo.update(ctx, input[0 ..< 30])
    sha512_256Algo.update(ctx, input[30 ..^ 1])
    check sha512_256Algo.final(ctx) == sha512_256Algo.sha512_256Hmac(k, input)
