import std/unittest

import nimcypher/hashes/md5 as md5Algo
import nimcypher/hash as hashApi
import vectorutils

proc hex(s: string): seq[byte] = hexToBytes(s)

test "md5 RFC 1321 appendix A.5 suite":
  check md5Algo.md5(@[]) == hex("d41d8cd98f00b204e9800998ecf8427e")
  check md5Algo.md5(hex("61")) == hex("0cc175b9c0f1b6a831c399e269772661")
  check md5Algo.md5(hex("616263")) == hex("900150983cd24fb0d6963f7d28e17f72")
  var mdMsg: seq[byte]
  for c in "message digest":
    mdMsg.add(byte(c))
  check md5Algo.md5(mdMsg) == hex("f96b697d7cb7938d525a2f31aaf161d0")
  var alpha: seq[byte]
  for c in "abcdefghijklmnopqrstuvwxyz":
    alpha.add(byte(c))
  check md5Algo.md5(alpha) == hex("c3fcd3d76192e4007dfb496cca67e13b")
  var alnum: seq[byte]
  for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
    alnum.add(byte(c))
  check md5Algo.md5(alnum) == hex("d174ab98d277d9f5a5611c2c9f419d9f")
  var digits: seq[byte]
  for j in 0 ..< 8:
    for c in "1234567890":
      digits.add(byte(c))
  check md5Algo.md5(digits) == hex("57edf4a22be3c955ac49da2e2107b67a")

test "md5 incremental == one-shot incl pad boundaries":
  var input: seq[byte]
  for j in 0 ..< 200:
    input.add(byte(j * 7 + 1))
  let whole = md5Algo.md5(input)
  for split in [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 199]:
    var ctx: md5Algo.Md5Context
    md5Algo.init(ctx)
    if split > 0:
      md5Algo.update(ctx, input[0 ..< split])
    if split < input.len:
      md5Algo.update(ctx, input[split ..^ 1])
    check md5Algo.final(ctx) == whole
  var c2: md5Algo.Md5Context
  md5Algo.init(c2)
  for b in input:
    md5Algo.update(c2, [b])
  check md5Algo.final(c2) == whole
  # empty updates are no-ops
  var c3: md5Algo.Md5Context
  md5Algo.init(c3)
  md5Algo.update(c3, newSeq[byte](0))
  md5Algo.update(c3, input)
  check md5Algo.final(c3) == whole

test "hmac-md5 RFC 2202 one-shot":
  var k1 = newSeq[byte](16)
  for i in 0 ..< 16: k1[i] = 0x0b
  var m1: seq[byte]
  for c in "Hi There": m1.add(byte(c))
  check md5Algo.md5Hmac(k1, m1) == hex("9294727a3638bb1c13f48ef8158bfc9d")
  var m2: seq[byte]
  for c in "what do ya want for nothing?": m2.add(byte(c))
  check md5Algo.md5Hmac(hex("4a656665"), m2) ==
    hex("750c783e6ab0b503eaa86e310a5db738")
  var k3 = newSeq[byte](16)
  for i in 0 ..< 16: k3[i] = 0xaa
  var d3 = newSeq[byte](50)
  for i in 0 ..< 50: d3[i] = 0xdd
  check md5Algo.md5Hmac(k3, d3) == hex("56be34521d144c88dbb8c733f0e8b3f6")
  var k4 = newSeq[byte](25)
  for i in 0 ..< 25: k4[i] = byte(i + 1)
  var d4 = newSeq[byte](50)
  for i in 0 ..< 50: d4[i] = 0xcd
  check md5Algo.md5Hmac(k4, d4) == hex("697eaf0aca3a3aea3a75164746ffaa79")
  # key larger than the block is hashed first (RFC 2202 case 6)
  var k6 = newSeq[byte](80)
  for i in 0 ..< 80: k6[i] = 0xaa
  var m6: seq[byte]
  for c in "Test Using Larger Than Block-Size Key - Hash Key First":
    m6.add(byte(c))
  check md5Algo.md5Hmac(k6, m6) == hex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")

test "hmac-md5 incremental == one-shot":
  var key: seq[byte]
  for j in 0 ..< 20:
    key.add(byte(j + 3))
  var input: seq[byte]
  for j in 0 ..< 100:
    input.add(byte(j * 5))
  let whole = md5Algo.md5Hmac(key, input)
  var ctx: md5Algo.Md5HmacContext
  md5Algo.initHmac(ctx, key)
  md5Algo.update(ctx, input[0 ..< 40])
  md5Algo.update(ctx, input[40 ..^ 1])
  check md5Algo.final(ctx) == whole

test "hmac-md5 empty key equals zero-padded key":
  let msg = hex("616263646566")
  check md5Algo.md5Hmac(newSeq[byte](0), msg) ==
    md5Algo.md5Hmac(newSeq[byte](64), msg)

test "high-level md5 api":
  check hashApi.md5("abc") == md5Algo.md5(hex("616263"))
  check hashApi.md5Hex("abc") == "900150983CD24FB0D6963F7D28E17F72"
  check hashApi.md5Hex("") == "D41D8CD98F00B204E9800998ECF8427E"
  check hashApi.md5HmacHex("Jefe", "what do ya want for nothing?") ==
    "750C783E6AB0B503EAA86E310A5DB738"
  var st = hashApi.initMd5()
  st.update("a")
  st.update("bc")
  check st.finish() == md5Algo.md5(hex("616263"))
  var st2 = hashApi.initMd5()
  st2.update("abc")
  check st2.finishHex() == hashApi.md5Hex("abc")
  var hm = hashApi.initMd5Hmac("Jefe")
  hm.update("what do ya want ")
  hm.update("for nothing?")
  check hm.finish() == md5Algo.md5Hmac(hex("4a656665"),
    hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f"))
  expect ValueError:
    discard st.finish()
