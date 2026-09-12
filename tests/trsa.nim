# Tests for RSA: PKCS#1 v1.5, PSS, OAEP, key generation.
#
# The fixed 1024-bit key was generated with `openssl genrsa 1024`; the
# PKCS#1 v1.5 test signature was made with
# `openssl dgst -sha256 -sign key.pem msg.bin` over
# "nimcypher interop test message", so it cross-validates against OpenSSL.
import std/unittest

import bigints
import nimcypher/algos/bigint_ext
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/utils
import vectorutils

proc hb(s: string): BigInt = fromBytesBE(hexToBytes(s))

const
  nHex = "C1EC046643E292B7A592FB69412DC95FF11B69B4A5EC4B52E3D0B539CE" &
    "5D7D1618C51E37A2C78BD16A5A24C9D398871C00898E53DC196D252FDD7A" &
    "6B0D8D0D4B1BF807FD5B5533202D758934425967349D097CB788892256EA" &
    "5515BC335D487EC7E1ACB37F522705E5E4D53FD4CC28C6F455F9BF4663D4" &
    "A441DF1688475AB843"
  dHex = "B39E4808ED320D11BB7464187EFDC8FB6BD92754E326F631E5BFE84C8" &
    "DBFFC5F9E3BDE9C4BD326C7A709ADEF9F65352813BB55B0893AA7E4FCEBD" &
    "93B1547241A63B00D9D0E724C00D99DDA2527FB2C82EF7289C444DBCCFC6B" &
    "BFAD747F9E3151ADF9629536D00B249162D31A33EDF2DB5B1DBC7050F004" &
    "4CE564BA7992FB9521"
  pHex = "E95A5A767DF2B25CAFD0518B6F333DFAC2CCC23849FB2E68AFA2A8A88" &
    "22D52D17C781A21039B8327D9054B8ADA1432A1C5D64492B6EEA06D07AF9" &
    "A2E5CA49EF1"
  qHex = "D4BE007793B535BAC8A5734BAE969A86BA9F683A47FAD26A45C33C35F" &
    "A655E043D900A3D0D7B542E0629717863D318A1F63D83FBD9793483F9639" &
    "2D844A07273"
  # openssl dgst -sha256 -sign over "nimcypher interop test message"
  osslSigHex = "B662894A914E3E0A9221E168987173076CEBA11F81EBCD89CCE87E14" &
    "42550410976F229C389DE8AE89495E0D73DA10696E80745B250C6C0C90083" &
    "AB462CB8AF834A768EE2C6F48D3EA53D256746BC198761FAF119FB4AA216" &
    "989081572323A065D06CFD500DF8A380D604F4404FF3AC70AF77CC1D58EB" &
    "AF6632878CD4C287355"

proc fixedKey(): RsaPrivateKey =
  rsaAlgo.rsaPrivateKey(hb(nHex), initBigInt(65537), hb(dHex),
                        hb(pHex), hb(qHex))

suite "rsa pkcs1v15":
  test "fixed key loads with k=128":
    let k = fixedKey()
    check k.k == 128
    check publicKey(k).k == 128

  test "openssl signature verifies (interoperability)":
    let k = fixedKey()
    let msg = toBytes("nimcypher interop test message")
    check pkcs1v15Verify(publicKey(k), rhSha256, msg, hexToBytes(osslSigHex))

  test "openssl signature rejects wrong message":
    let k = fixedKey()
    check not pkcs1v15Verify(publicKey(k), rhSha256, toBytes("tampered"),
                             hexToBytes(osslSigHex))

  test "sign/verify roundtrip for SHA-256/384/512":
    var k = fixedKey()
    let msg = toBytes("hello JOSE")
    for h in [rhSha256, rhSha384, rhSha512]:
      let sig = pkcs1v15Sign(k, h, msg)
      check sig.len == 128
      check pkcs1v15Verify(publicKey(k), h, msg, sig)
    wipe(k)

  test "tampered signature fails":
    var k = fixedKey()
    let msg = toBytes("hello JOSE")
    var sig = pkcs1v15Sign(k, rhSha256, msg)
    sig[10] = sig[10] xor 0x01
    check not pkcs1v15Verify(publicKey(k), rhSha256, msg, sig)
    wipe(k)

  test "wrong hash fails":
    var k = fixedKey()
    let msg = toBytes("hello JOSE")
    let sig = pkcs1v15Sign(k, rhSha256, msg)
    check not pkcs1v15Verify(publicKey(k), rhSha384, msg, sig)
    wipe(k)

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

suite "rsa pss":
  test "sign/verify roundtrip for SHA-256/384":
    var k = fixedKey()
    let msg = toBytes("pss message")
    for h in [rhSha256, rhSha384]:
      let sig = pssSign(k, h, msg)
      check sig.len == 128
      check pssVerify(publicKey(k), h, msg, sig)
    wipe(k)

  test "sign/verify roundtrip for SHA-512 (2048-bit key)":
    # PSS with saltLen = hashLen needs emLen >= 2*hLen + 2.
    var k = fixedKey2048()
    let msg = toBytes("pss message 512")
    let sig = pssSign(k, rhSha512, msg)
    check sig.len == 256
    check pssVerify(publicKey(k), rhSha512, msg, sig)
    wipe(k)

  test "openssl signature verifies (interoperability)":
    # openssl dgst -sha256 -sigopt rsa_padding_mode:pss
    #   -sigopt rsa_pss_saltlen:32 -sign over "nimcypher interop test message"
    let k = fixedKey()
    let sig = hexToBytes("94E61F269AB85D176B7F93ED11528CF6C62F0CE6D8FA" &
      "92BAC49F74D28E9C2BE8AA4C7A21CB72E925E53FE12CA10356226E348FC6B" &
      "0927385E75FB34FE8F1AC768DFA2DC7F8CE9717B0FF4F9F5FB3190662884AD" &
      "8E9C785B037686784B123B2FABF53EF9C3B794C33B289FEBC1CA97765ED6B" &
      "23DF4637F050BDCE2A7C55193660")
    check pssVerify(publicKey(k), rhSha256,
                    toBytes("nimcypher interop test message"), sig)

  test "tampered signature fails":
    var k = fixedKey()
    let msg = toBytes("pss message")
    var sig = pssSign(k, rhSha256, msg)
    sig[^1] = sig[^1] xor 0x01
    check not pssVerify(publicKey(k), rhSha256, msg, sig)
    wipe(k)

suite "rsa oaep":
  test "encrypt/decrypt roundtrip SHA-1 and SHA-256":
    var k = fixedKey()
    let msg = toBytes("secret bytes")
    for h in [rhSha1, rhSha256]:
      let c = oaepEncrypt(publicKey(k), h, msg)
      check c.len == 128
      check oaepDecrypt(k, h, c) == msg
    wipe(k)

  test "openssl ciphertext decrypts (interoperability)":
    # openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep
    #   -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
    # over "nimcypher interop test message"
    var k = fixedKey()
    let c = hexToBytes("12CF1ABCCE0D349A0EA413CE5EC137C212E564ABB385397" &
      "5F4E669483F3104E29FA0892CE9569F68EFA82028D7CC24D84D08AC7BC29F" &
      "A371E96B901A78C0CF49541B183237F041DC95CE2C1A9857EAFD479C2DB61" &
      "8EDDD0BA7FB66309A983532D0C25191226777867F17016EA94A4329138986" &
      "D9555D5457CA8A46FB7485C569")
    check oaepDecrypt(k, rhSha256, c) == toBytes("nimcypher interop test message")
    wipe(k)

  test "tampered ciphertext fails":
    var k = fixedKey()
    let msg = toBytes("secret bytes")
    var c = oaepEncrypt(publicKey(k), rhSha256, msg)
    c[20] = c[20] xor 0x01
    expect ValueError:
      discard oaepDecrypt(k, rhSha256, c)
    wipe(k)

  test "message too long raises":
    let k = fixedKey()
    expect ValueError:
      discard oaepEncrypt(publicKey(k), rhSha256, newSeq[byte](128))

suite "rsa pkcs1v15 encryption":
  test "encrypt/decrypt roundtrip incl. empty and max length":
    var k = fixedKey()
    check pkcs1v15Decrypt(k, pkcs1v15Encrypt(publicKey(k), @[])) == newSeq[byte]()
    let maxMsg = newSeq[byte](128 - 11)
    let c = pkcs1v15Encrypt(publicKey(k), maxMsg)
    check c.len == 128
    check pkcs1v15Decrypt(k, c) == maxMsg
    check pkcs1v15Decrypt(k, pkcs1v15Encrypt(publicKey(k),
      toBytes("secret bytes"))) == toBytes("secret bytes")
    wipe(k)

  test "openssl ciphertext decrypts (interoperability)":
    # printf 'RSA1_5 interop' | openssl pkeyutl -encrypt -pubin
    #   -inkey <fixedKey pub PEM> -pkeyopt rsa_padding_mode:pkcs1
    var k = fixedKey()
    let c = hexToBytes("9CE1E0A0ACD36478AC1AC18B32BF46C58951FBC33F3316" &
      "112049C2DDFB8CB9AC8F28DC323822711131EFA6071391CDAAE9276877B88" &
      "2FA8C57F5061C1EF6CA2439584C6BB1CBAD4D889127A09BDC4299076A245A" &
      "FF5FA7E41FCCDBF42022024C260C0FD0221319E7797915F879E4AFC743F88" &
      "42D836EA6970300B22025CD8AB9")
    check pkcs1v15Decrypt(k, c) == toBytes("RSA1_5 interop")
    wipe(k)

  test "tampered ciphertext fails":
    var k = fixedKey()
    var c = pkcs1v15Encrypt(publicKey(k), toBytes("secret bytes"))
    c[20] = c[20] xor 0x01
    expect ValueError:
      discard pkcs1v15Decrypt(k, c)
    wipe(k)

  test "message too long raises":
    let k = fixedKey()
    expect ValueError:
      discard pkcs1v15Encrypt(publicKey(k), newSeq[byte](128 - 10))

suite "rsa keygen":
  test "512-bit key generates and roundtrips":
    var k = generateRsaKeyPair(512)
    check k.k == 64
    let msg = toBytes("keygen smoke")
    let sig = pkcs1v15Sign(k, rhSha256, msg)
    check pkcs1v15Verify(publicKey(k), rhSha256, msg, sig)
    # 512-bit key only fits OAEP-SHA1 (k - 2*hLen - 2 = 22 bytes)
    let c = oaepEncrypt(publicKey(k), rhSha1, msg)
    check oaepDecrypt(k, rhSha1, c) == msg
    wipe(k)
