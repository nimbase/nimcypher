import std/unittest

import nimcypher/algos/sha256 as sha256Algo
import nimcypher/hash as hashApi
import vectorutils

proc hex(s: string): seq[byte] = hexToBytes(s)

test "sha256 FIPS 180-4 vectors":
  check sha256Algo.sha256(@[]) == hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  check sha256Algo.sha256(hex("616263")) == hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  var msg3: seq[byte]
  for c in "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
    msg3.add byte(c)
  check sha256Algo.sha256(msg3) == hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

test "sha256 one million a":
  var msg = newSeq[byte](1_000_000)
  for i in 0 ..< msg.len:
    msg[i] = byte('a')
  check sha256Algo.sha256(msg) == hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

test "sha256 incremental == one-shot incl split inside pad":
  var input: seq[byte]
  for j in 0 ..< 200:
    input.add(byte(j * 3))
  let whole = sha256Algo.sha256(input)
  var ctx: sha256Algo.Sha256Context
  sha256Algo.init(ctx)
  sha256Algo.update(ctx, input[0 ..< 55])
  sha256Algo.update(ctx, input[55 ..< 64])
  sha256Algo.update(ctx, input[64 ..^ 1])
  check sha256Algo.final(ctx) == whole
  # single-byte chunks
  var c2: sha256Algo.Sha256Context
  sha256Algo.init(c2)
  for b in input:
    sha256Algo.update(c2, [b])
  check sha256Algo.final(c2) == whole

test "hmac-sha256 RFC 4231 one-shot":
  check sha256Algo.sha256Hmac(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                 hex("4869205468657265")) ==
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  check sha256Algo.sha256Hmac(hex("4a656665"),
                 hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")) ==
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  var k3 = newSeq[byte](20)
  for i in 0 ..< 20: k3[i] = 0xaa
  var d3 = newSeq[byte](50)
  for i in 0 ..< 50: d3[i] = 0xdd
  check sha256Algo.sha256Hmac(k3, d3) == hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
  check sha256Algo.sha256Hmac(hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                 hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")) ==
        hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")

test "hmac-sha256 long key (> block) RFC 4231 case 6":
  var k6 = newSeq[byte](131)
  for i in 0 ..< 131: k6[i] = 0xaa
  let d6 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
  check sha256Algo.sha256Hmac(k6, d6) == hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")

test "hmac incremental == one-shot":
  var key: seq[byte]
  for j in 0 ..< 32:
    key.add(byte(j + 1))
  var input: seq[byte]
  for j in 0 ..< 100:
    input.add(byte(j * 5))
  let whole = sha256Algo.sha256Hmac(key, input)
  var ctx: sha256Algo.Sha256HmacContext
  sha256Algo.initHmac(ctx, key)
  sha256Algo.update(ctx, input[0 ..< 40])
  sha256Algo.update(ctx, input[40 ..^ 1])
  check sha256Algo.final(ctx) == whole

test "hmac empty key equals zero-padded key":
  let msg = hex("616263646566")
  check sha256Algo.sha256Hmac(newSeq[byte](0), msg) ==
        sha256Algo.sha256Hmac(newSeq[byte](64), msg)

test "hkdf-sha256 RFC 5869 case 1":
  let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hex("000102030405060708090a0b0c")
  let info = hex("f0f1f2f3f4f5f6f7f8f9")
  let okm = hashApi.hkdfSha256(ikm, salt, info, 42)
  check okm == hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
  check okm.len == 42

test "high-level sha256 api":
  check hashApi.sha256("abc") == sha256Algo.sha256(hex("616263"))
  check hashApi.sha256Hex("abc") == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
  check hashApi.sha256HmacHex("Jefe", "what do ya want for nothing?") == "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"
  var st = hashApi.initSha256()
  st.update("a")
  st.update("bc")
  check st.finish() == sha256Algo.sha256(hex("616263"))
  var hm = hashApi.initSha256Hmac("Jefe")
  hm.update("what do ya want ")
  hm.update("for nothing?")
  check hm.finish() == sha256Algo.sha256Hmac(hex("4a656665"),
    hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f"))

test "hkdf-sha256 length cap":
  check hashApi.hkdfSha256(@[byte 1, 2, 3], @[], @[], 8160).len == 8160
  expect ValueError:
    discard hashApi.hkdfSha256(@[byte 1, 2, 3], @[], @[], 8161)
