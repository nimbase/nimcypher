# Standalone RSA benchmark (pure Nim, no FFI/nimcrypto deps).
# Run: nim c -r -d:danger --opt:speed --path:src tests/bench_rsa.nim
import std/monotimes
import std/times
import std/strformat

import bigints
import nimcypher/algos/bigint_ext
import nimcypher/algos/internal/montgomery
import nimcypher/algos/internal/montgomery64
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/utils
import vectorutils

proc hb(s: string): BigInt = fromBytesBE(hexToBytes(s))

proc fixedKey1024(): RsaPrivateKey =
  rsaAlgo.rsaPrivateKey(
    hb("C1EC046643E292B7A592FB69412DC95FF11B69B4A5EC4B52E3D0B539CE" &
      "5D7D1618C51E37A2C78BD16A5A24C9D398871C00898E53DC196D252FDD7A" &
      "6B0D8D0D4B1BF807FD5B5533202D758934425967349D097CB788892256EA" &
      "5515BC335D487EC7E1ACB37F522705E5E4D53FD4CC28C6F455F9BF4663D4" &
      "A441DF1688475AB843"),
    initBigInt(65537),
    hb("B39E4808ED320D11BB7464187EFDC8FB6BD92754E326F631E5BFE84C8" &
      "DBFFC5F9E3BDE9C4BD326C7A709ADEF9F65352813BB55B0893AA7E4FCEBD" &
      "93B1547241A63B00D9D0E724C00D99DDA2527FB2C82EF7289C444DBCCFC6B" &
      "BFAD747F9E3151ADF9629536D00B249162D31A33EDF2DB5B1DBC7050F004" &
      "4CE564BA7992FB9521"),
    hb("E95A5A767DF2B25CAFD0518B6F333DFAC2CCC23849FB2E68AFA2A8A88" &
      "22D52D17C781A21039B8327D9054B8ADA1432A1C5D64492B6EEA06D07AF9" &
      "A2E5CA49EF1"),
    hb("D4BE007793B535BAC8A5734BAE969A86BA9F683A47FAD26A45C33C35F" &
      "A655E043D900A3D0D7B542E0629717863D318A1F63D83FBD9793483F9639" &
      "2D844A07273"))

proc fixedKey2048(): RsaPrivateKey =
  rsaAlgo.rsaPrivateKey(
    hb("DF0E355551DD757CA1E1772925A84AA1436882A588DAF93A605206C7DD3B7CDD" &
       "86F02634E4B2FB4881453FCB685A76512F0E358CFA5A4AB20A4821B7F8E9E7ED" &
       "08DF16C2382B32B49356D752B79CB11E2EC13D50C3254C3417AF8300C2F82862" &
       "B230B17798A7C7026D157D8092D11BD606577DFC9867C152E115301196F7EBB4" &
       "D90F91E5951BB92A774225DECC6F8292C8DCDBC724341682322C26CF0DD24917" &
       "6FDF52575BA79D37ABBE08824A133124D09868B7D590426CBA3F5E8C6E573ED2" &
       "5E0F0BEB04BAC03DF506698D251A8F39FF9C8F68AF977BC1F243530750A1B817" &
       "F1483582270FC7282437F19BE16FE1228C10CEFABE6D3F256A6E3FDE39233815"),
    initBigInt(65537),
    hb("015B3642CF0D202E4253BB244268DC0F4FF81E3740764866ACF842B74B6695B3" &
       "492343B035A5CAF65D66DCE4F13CFF942DCB91D2CA20EB6C5AB8A68FD65121CA" &
       "64AFEA9502BF6C7F01985915D52CFC3CB93F0E8EE3A8E1E63D30A184CB2AB420" &
       "2982374A096117CA317C9C77402D4A548A5454DD48D5F4AC7AD6E4A46EBD122F" &
       "53EC82C4756CC732E38792DB539B6E9928BA234C2BB9443DA83B100A50E3C3E8" &
       "4D32B7A4E7E38E15716A6409EE8C3B3894A708DCBAC77B1213CA52C8C5CE4BCC" &
       "80DC320F375E201CB9CA13F9058DDCC261771CDDBAB566F752DB3B05FC4B6C1D" &
       "CE579E09CFB082727E14426A952C0463128A9BE9DABD5F2A0B2738BBAA4D8C6F"),
    hb("F2D0A2E2186F78172E579F8740DCC79C6D10AEDA0D50A397516C1548D56B6551" &
       "CB533FF59F5061507BB1735F79FE81AE7FEC2DB75DA27433ADC6855565A4786D" &
       "594E66D06F7223104F167F348A8CC7B7D6B4BE6E566B7D9F14E2BCB075095C66" &
       "4CD056DE632D752876D9716129EF85553DF04B4D832D09E842C6783FB4562E67"),
    hb("EB2AE565A6EB73B7EA81905D0764584B44CD1F8EF67CAFAC95204176347ECA08" &
       "62B025E56888131C821025264A5ADB4449DA79778B632444B38FED639F9ECB05" &
       "328E96B4CEE1852EFF09718257D15A248B84FE5E8420F5A3C82499699AC5624A" &
       "E230515B06CF480A4291410DB1035F4716712A67C0BA01945190156C63422023"))

var sink: byte

proc timeIt(iters: int, f: proc() {.closure.}): float =
  f() # warmup (also catches errors early)
  let start = getMonoTime()
  for _ in 0 ..< iters:
    f()
  result = (getMonoTime() - start).inNanoseconds.float / 1e9

proc msPerOp(total: float, iters: int): string =
  fmt"{total / iters.float * 1000:.1f}ms/op ({iters.float / total:.1f}/s)"

when isMainModule:
  let msg = toBytes("hello JOSE benchmark message")
  echo "RSA benchmark (pure Nim, bigints backend)"
  echo ""

  for (name, kp) in [("1024", fixedKey1024()), ("2048", fixedKey2048())]:
    var key = kp
    let pub = publicKey(key)
    echo fmt"== RSA-{name} =="
    # iters: private ops are slow; keep runtime sane
    let privIters = if name == "1024": 10 else: 3
    let pubIters = if name == "1024": 200 else: 100

    var sig = pkcs1v15Sign(key, rhSha256, msg)
    let tSign = timeIt(privIters, proc() =
      let s = pkcs1v15Sign(key, rhSha256, msg)
      sink = sink xor s[0])
    echo fmt"  pkcs1v15 sign   : {tSign:.3f}s total {msPerOp(tSign, privIters)}"

    let tVerify = timeIt(pubIters, proc() =
      let ok = pkcs1v15Verify(pub, rhSha256, msg, sig)
      sink = sink xor byte(ord(ok)))
    echo fmt"  pkcs1v15 verify : {tVerify:.3f}s total {msPerOp(tVerify, pubIters)}"

    let tPssSign = timeIt(privIters, proc() =
      let s = pssSign(key, rhSha256, msg)
      sink = sink xor s[0])
    echo fmt"  pss sign        : {tPssSign:.3f}s total {msPerOp(tPssSign, privIters)}"

    var psig = pssSign(key, rhSha256, msg)
    let tPssVerify = timeIt(pubIters, proc() =
      let ok = pssVerify(pub, rhSha256, msg, psig)
      sink = sink xor byte(ord(ok)))
    echo fmt"  pss verify      : {tPssVerify:.3f}s total {msPerOp(tPssVerify, pubIters)}"

    let h = if name == "1024": rhSha256 else: rhSha256
    var ct = oaepEncrypt(pub, h, msg)
    let tEnc = timeIt(pubIters, proc() =
      let c = oaepEncrypt(pub, h, msg)
      sink = sink xor c[0])
    echo fmt"  oaep encrypt    : {tEnc:.3f}s total {msPerOp(tEnc, pubIters)}"

    let tDec = timeIt(privIters, proc() =
      let m = oaepDecrypt(key, h, ct)
      sink = sink xor m[0])
    echo fmt"  oaep decrypt    : {tDec:.3f}s total {msPerOp(tDec, privIters)}"
    echo ""

  # ---- breakdown of one 2048-bit private op ----
  echo "== breakdown: one RSA-2048 pkcs1v15 sign =="
  var k2048 = fixedKey2048()
  let n = 5
  # full sign
  let tFull = timeIt(n, proc() =
    let s = pkcs1v15Sign(k2048, rhSha256, msg)
    sink = sink xor s[0])
  echo fmt"  full sign            : {msPerOp(tFull, n)}"
  # conversions: fromBytesBE + toBytesBE on 256-byte values
  let em = block:
    var tmp = newSeq[byte](256)
    for i in 0 ..< 256: tmp[i] = byte(i)
    tmp
  let big = fromBytesBE(em)
  let tFrom = timeIt(200, proc() =
    let b = fromBytesBE(em)
    sink = sink xor byte(byteLen(b) and 0xFF))
  echo fmt"  fromBytesBE(256B)    : {msPerOp(tFrom, 200)}"
  let tTo = timeIt(200, proc() =
    let o = toBytesBE(big, 256)
    sink = sink xor o[0])
  echo fmt"  toBytesBE(256B)      : {msPerOp(tTo, 200)}"
  # raw CRT halves via Montgomery fast path (1024-bit exp)
  let tCrt = timeIt(n, proc() =
    let m1 = fastPowmod((big mod k2048.p), k2048.dp, k2048.p)
    let m2 = fastPowmod((big mod k2048.q), k2048.dq, k2048.q)
    sink = sink xor byte(byteLen(m1 + m2) and 0xFF))
  echo fmt"  2x CRT fastPowmod    : {msPerOp(tCrt, n)}"
  # blinding overhead as in rsa.privateOpBlinded: r sampling + gcd +
  # fastInvmod + fast r^e
  let one = initBigInt(1)
  let tBlind = timeIt(n, proc() =
    var r = randomBigIntBelow(k2048.n)
    doAssert gcd(r, k2048.n) == one
    let ri = fastInvmod(r, k2048.n)
    let re = fastPowmod(r, k2048.e, k2048.n)
    sink = sink xor byte(byteLen(ri + re) and 0xFF))
  echo fmt"  blinding (r+gcd+inv+r^e): {msPerOp(tBlind, n)}"
  echo fmt"  full-vs-parts check : full {tFull/n.float*1000:.1f}ms vs crt {tCrt/n.float*1000:.1f}ms + blind {tBlind/n.float*1000:.1f}ms"
  echo "checksum: ", sink
