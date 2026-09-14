import std/unittest

import nimcypher/utils
import nimcypher/hashes/xxhash as xxhAlgo
import nimcypher/hash as hashApi

{.push checks: off.}
proc sanityBuf(n: int): seq[byte] =
  ## Official xxHash sanity buffer: byteGen = PRIME32, top byte kept.
  result = newSeq[byte](n)
  var g = 2654435761'u64
  for i in 0 ..< n:
    result[i] = byte(g shr 56)
    g = g * 11400714785074694797'u64
{.pop.}

let buf = sanityBuf(4161)

proc prefix(ln: int): seq[byte] =
  if ln == 0: newSeq[byte](0) else: @(buf.toOpenArray(0, ln - 1))

const
  SeedPrime32 = 0x9E3779B1'u32

test "xxh32 sanity buffer vectors match reference xxhash":
  const tv: array[14, tuple[len: int, h32: uint32]] = [
    (0, 0x02CC5D05'u32), (1, 0xCF65B03E'u32), (4, 0xA9DE7CE9'u32),
    (14, 0x1208E7E2'u32), (15, 0x6B859E14'u32), (16, 0x93BA3759'u32),
    (17, 0x89FDC23E'u32), (32, 0xD89829EC'u32), (33, 0x31A427E5'u32),
    (100, 0x96AD8143'u32), (240, 0xFA6B6557'u32), (241, 0xE5F7C54D'u32),
    (1000, 0x2052D698'u32), (4161, 0xACF41462'u32),
  ]
  for (ln, h) in tv:
    check xxhAlgo.xxh32(prefix(ln), 0) == h
  # empty input: pass an empty slice safely via a zero-length seq
  check xxhAlgo.xxh32(newSeq[byte](0), 0) == 0x02CC5D05'u32
  check xxhAlgo.xxh32(newSeq[byte](0), SeedPrime32) == 0x36B78AE7'u32
  check xxhAlgo.xxh32(buf.toOpenArray(0, 0), 0) == 0xCF65B03E'u32
  check xxhAlgo.xxh32(buf.toOpenArray(0, 99), SeedPrime32) == 0x83D48124'u32
  check xxhAlgo.xxh32(buf.toOpenArray(0, 240), SeedPrime32) == 0x13B52081'u32
  check hashApi.xxh32("abc", 0) == 0x32D153FF'u32

test "xxh64 sanity buffer vectors match reference xxhash":
  const tv: array[14, tuple[len: int, h64: uint64]] = [
    (0, 0xEF46DB3751D8E999'u64), (1, 0xE934A84ADB052768'u64),
    (4, 0x9136A0DCA57457EE'u64), (15, 0x180719316D622D84'u64),
    (16, 0x98C90B57FDFCB55C'u64), (17, 0x0D39A2D051A30C2Cu64),
    (32, 0x18B216492BB44B70'u64), (33, 0x55C8DC3E578F5B59'u64),
    (100, 0x4BFE019CD91D9EA4'u64), (240, 0xB81838D483BAEE53'u64),
    (241, 0x95D76C8B4D8FC4D6'u64), (1000, 0x52BD1358F22E9EF7'u64),
    (100, 0x4BFE019CD91D9EA4'u64), (4161, 0xCD3D6DF2DB509A75'u64),
  ]
  for (ln, h) in tv:
    check xxhAlgo.xxh64(prefix(ln), 0) == h
  check hashApi.xxh64("abc", 0) == 0x44BC2CF5AD770999'u64

test "xxh3_64 sanity buffer vectors match reference xxhash":
  const tv: array[14, tuple[len: int, h: uint64]] = [
    (0, 0x2D06800538D394C2'u64), (1, 0xC44BDFF4074EECDB'u64),
    (4, 0xE5DC74BC51848A51'u64), (14, 0x1AC0BBDA2B9FCF03'u64),
    (15, 0x45556D4D6E1798BC'u64), (16, 0x981B17D36C7498C9'u64),
    (17, 0x796F5ACD3A60F862'u64), (32, 0x9FEADDBDBF57EED3'u64),
    (33, 0xABFB2D081B400A10'u64), (100, 0x93CD95432B7D483F'u64),
    (240, 0x81C3C2B67F568CCF'u64), (241, 0xC5A639ECD2030E5E'u64),
    (1000, 0xACA2DDE0F1951B9A'u64), (4161, 0xEFB6CCB06C0B206A'u64),
  ]
  for (ln, h) in tv:
    check xxhAlgo.xxh3_64bits(prefix(ln)) == h
  check hashApi.xxh3_64bits("abc") == 0x78AF5F94892F3950'u64
  check xxhAlgo.xxh3_64bits_withSeed(buf.toOpenArray(0, 99), 0) ==
    xxhAlgo.xxh3_64bits(buf.toOpenArray(0, 99))

test "xxh128 sanity buffer vectors match reference xxhash":
  const tv: array[11, tuple[len: int, hexd: string]] = [
    (0, "99AA06D3014798D86001C324468D497F"),
    (1, "A6CD5E9392000F6AC44BDFF4074EECDB"),
    (4, "970D585AC632BF8E2E7D8D6876A39FE9"),
    (16, "C68C368ECF8A9C05562980258A998629"),
    (17, "955FA78643ED3669ABBC12D11973D7DB"),
    (32, "98FC6458710DC2E8278410A17595E3F9"),
    (100, "9B50B05817AB158E5FCBC2E3295F2476"),
    (240, "AA4202DAA2769DC85C9AAE94C8EBE5A0"),
    (241, "99A80ECF0ECFC647C5A639ECD2030E5E"),
    (1000, "9B857ABF662E5A25ACA2DDE0F1951B9A"),
    (4161, "06E30DA044FBC01EEFB6CCB06C0B206A"),
  ]
  for (ln, hx) in tv:
    check hashApi.xxh128Hex(prefix(ln)) == hx
  check hashApi.xxh128Hex("abc") == "06B05AB6733A618578AF5F94892F3950"
  check xxhAlgo.xxh128(toBytes("abc"), 0) == xxhAlgo.xxh3_128bits(toBytes("abc"))

test "xxh32 streaming == one-shot at stripe boundaries":
  for ln in [15, 16, 17, 31, 32, 33, 100]:
    let whole = xxhAlgo.xxh32(buf.toOpenArray(0, ln - 1), 0)
    for split in [0, 1, 7, 15, 16, 17, 32, 33, 99]:
      if split > ln:
        continue
      var st: xxhAlgo.Xxh32State
      xxhAlgo.reset(st, 0)
      if split > 0:
        xxhAlgo.update(st, buf.toOpenArray(0, split - 1))
      if split < ln:
        xxhAlgo.update(st, buf.toOpenArray(split, ln - 1))
      check xxhAlgo.digest(st) == whole
    # byte at a time
    var bs: xxhAlgo.Xxh32State
    xxhAlgo.reset(bs, SeedPrime32)
    for i in 0 ..< ln:
      xxhAlgo.update(bs, buf.toOpenArray(i, i))
    check xxhAlgo.digest(bs) == xxhAlgo.xxh32(buf.toOpenArray(0, ln - 1),
                                              SeedPrime32)

test "xxh64 streaming == one-shot at stripe boundaries":
  for ln in [31, 32, 33, 63, 64, 65, 200]:
    let whole = xxhAlgo.xxh64(buf.toOpenArray(0, ln - 1), 0)
    for split in [0, 1, 7, 31, 32, 33, 64, 65, 199]:
      if split > ln:
        continue
      var st: xxhAlgo.Xxh64State
      xxhAlgo.reset(st, 0)
      if split > 0:
        xxhAlgo.update(st, buf.toOpenArray(0, split - 1))
      if split < ln:
        xxhAlgo.update(st, buf.toOpenArray(split, ln - 1))
      check xxhAlgo.digest(st) == whole

test "xxh3 streaming == one-shot across size classes":
  for ln in [0, 1, 3, 4, 8, 9, 16, 17, 100, 128, 129, 200, 240, 241,
             500, 1024, 1500]:
    let data = prefix(ln)
    var s64: xxhAlgo.Xxh3State
    xxhAlgo.resetXxh3(s64, xxhAlgo.xxh3_64, 0)
    var s128: xxhAlgo.Xxh3State
    xxhAlgo.resetXxh3(s128, xxhAlgo.xxh3_128, 0)
    # split into odd chunks incl. byte at a time for short inputs
    var pos = 0
    let step = if ln <= 32: 1 else: 37
    while pos < ln:
      let nxt = min(pos + step, ln)
      xxhAlgo.update(s64, buf.toOpenArray(pos, nxt - 1))
      xxhAlgo.update(s128, buf.toOpenArray(pos, nxt - 1))
      pos = nxt
    check xxhAlgo.digest64(s64) == xxhAlgo.xxh3_64bits(data)
    check xxhAlgo.digest128(s128) == xxhAlgo.xxh3_128bits(data)

test "xxh seeded vectors match reference xxhash":
  # (length, seed, xxh32, xxh64, xxh3_64, xxh128) from the reference
  # implementation over the sanity buffer above.
  const tv = [
    (300, 2155511622373988895'u64, "33DADDD2", "24ED2DF6EB6C1E2C",
     "7F145E7D13F06F5C", "7D5FEE26D3B971467F145E7D13F06F5C"),
    (0, 16804540376168033093'u64, "5C31E6A5", "3159D27D513509E1",
     "86CE03908F6EF7C5", "39D9427F94F77BCD9D4C27265C2FE3E5"),
    (1000, 644274044980223449'u64, "E723357C", "9825628391BB0D1C",
     "B02C9C062221EECD", "3AD010FEB09A5401B02C9C062221EECD"),
    (239, 1548387003684236636'u64, "AB8F483D", "5A6F037BBB0DF3A2",
     "F16B7D8006E495D1", "E52DD7280D01CEFAD2722F64C882CD7A"),
  ]
  for (ln, seed, h32, h64, h3, h128) in tv:
    let d = prefix(ln)
    check hashApi.xxh32Hex(d, uint32(seed and 0xFFFFFFFF'u64)) == h32
    check hashApi.xxh64Hex(d, seed) == h64
    check hashApi.xxh3_64bitsHex(d, seed) == h3
    check hashApi.xxh128Hex(d, seed) == h128

test "xxh3 seeded streaming matches one-shot":
  let data = prefix(1000)
  var s: xxhAlgo.Xxh3State
  xxhAlgo.resetXxh3(s, xxhAlgo.xxh3_64, 0x9E3779B97F4A7C15'u64)
  xxhAlgo.update(s, buf.toOpenArray(0, 499))
  xxhAlgo.update(s, buf.toOpenArray(500, 999))
  check xxhAlgo.digest64(s) ==
    xxhAlgo.xxh3_64bits_withSeed(data, 0x9E3779B97F4A7C15'u64)
  var s2: xxhAlgo.Xxh3State
  xxhAlgo.resetXxh3(s2, xxhAlgo.xxh3_128, 12345'u64)
  xxhAlgo.update(s2, data)
  check xxhAlgo.digest128(s2) == xxhAlgo.xxh3_128bits_withSeed(data, 12345'u64)

test "xxh3 withSecret behavior":
  # short inputs: secret+seed acts like seed alone
  check xxhAlgo.xxh3_64bits_withSecretAndSeed(buf.toOpenArray(0, 99),
    buf.toOpenArray(7, 157), 0x1234'u64) ==
    xxhAlgo.xxh3_64bits_withSeed(buf.toOpenArray(0, 99), 0x1234'u64)
  check xxhAlgo.xxh3_128bits_withSecretAndSeed(buf.toOpenArray(0, 199),
    buf.toOpenArray(7, 157), 99'u64) ==
    xxhAlgo.xxh3_128bits_withSeed(buf.toOpenArray(0, 199), 99'u64)
  # large inputs: secret+seed acts like the secret alone
  let big = prefix(1000)
  check xxhAlgo.xxh3_64bits_withSecretAndSeed(big, buf.toOpenArray(7, 157),
    0x1234'u64) == xxhAlgo.xxh3_64_withSecret(big, buf.toOpenArray(7, 157))
  check xxhAlgo.xxh3_128bits_withSecretAndSeed(big, buf.toOpenArray(7, 157),
    99'u64) == xxhAlgo.xxh3_128_withSecret(big, buf.toOpenArray(7, 157))
  # streaming with secret matches one-shot
  var st: xxhAlgo.Xxh3State
  xxhAlgo.resetXxh3WithSecret(st, xxhAlgo.xxh3_64, buf.toOpenArray(7, 157))
  xxhAlgo.update(st, buf.toOpenArray(0, 499))
  xxhAlgo.update(st, buf.toOpenArray(500, 999))
  check xxhAlgo.digest64(st) ==
    xxhAlgo.xxh3_64_withSecret(big, buf.toOpenArray(7, 157))
  # short secrets are rejected
  expect ValueError:
    discard xxhAlgo.xxh3_64_withSecret(big, buf.toOpenArray(0, 99))
  # secret generator produces usable secrets of any allowed size
  var sec = newSeq[byte](192)
  xxhAlgo.generateSecret(sec, toBytes("custom-seed"))
  check xxhAlgo.xxh3_64_withSecret(big, sec) ==
    xxhAlgo.xxh3_64_withSecret(big, sec)

test "high-level xxhash api":
  check hashApi.xxh32("abc") == 0x32D153FF'u32
  check hashApi.xxh32Hex("abc") == "32D153FF"
  check hashApi.xxh64("abc") == 0x44BC2CF5AD770999'u64
  check hashApi.xxh64Hex("abc") == "44BC2CF5AD770999"
  check hashApi.xxh3_64bits("abc") == 0x78AF5F94892F3950'u64
  check hashApi.xxh3_64bitsHex("abc") == "78AF5F94892F3950"
  check hashApi.xxh128Hex("abc") == "06B05AB6733A618578AF5F94892F3950"
  var a = hashApi.initXxh32()
  a.update("a")
  a.update("bc")
  check a.finish() == hashApi.xxh32("abc")
  var b = hashApi.initXxh64()
  b.update("a")
  b.update("bc")
  check b.finish() == hashApi.xxh64("abc")
  var b2 = hashApi.initXxh64()
  b2.update("abc")
  check b2.finishHex() == hashApi.xxh64Hex("abc")
  var c = hashApi.initXxh3_64()
  c.update("a")
  c.update("bc")
  check c.finish() == hashApi.xxh3_64bits("abc")
  var d = hashApi.initXxh3_128()
  d.update("a")
  d.update("bc")
  check d.finishHex() == hashApi.xxh128Hex("abc")
  expect ValueError:
    discard a.finish()
