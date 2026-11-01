# Key import tests against openssl-generated keys.
# Skips without openssl on PATH (same convention as topenssl).
import std/os
import std/osproc
import std/unittest

import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/utils
import nimcypher/tls/keys

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

proc run(dir, cmd: string) =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "openssl failed: " & cmd & "\n" & outp)

suite "key import":
  if osslBin == "":
    if requireOssl:
      raise newException(OSError, "openssl missing but required")
    echo "SKIP ttls_keys: openssl not on PATH"
  else:
    let dir = getTempDir() / "nimcypher_ttls_keys"
    createDir(dir)
    run(dir, osslBin & " genrsa -out rsa.pem 2048")
    run(dir, osslBin & " rsa -in rsa.pem -outform DER -out rsa_pkcs1.der")
    run(dir, osslBin & " pkcs8 -topk8 -nocrypt -in rsa.pem " &
      "-out rsa_pkcs8.pem -outform PEM")
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ec.pem")
    run(dir, osslBin & " pkcs8 -topk8 -nocrypt -in ec.pem " &
      "-out ec_pkcs8.pem -outform PEM")
    run(dir, osslBin & " genpkey -algorithm ed25519 -out ed.pem")
    run(dir, osslBin & " genpkey -algorithm x25519 -out x.pem")

    test "rsa pkcs1 der + pkcs8 pem agree":
      let k1 = loadPrivateKeyDer(toBytes(readFile(dir / "rsa_pkcs1.der")))
      let k2 = loadPrivateKeyPem(readFile(dir / "rsa_pkcs8.pem"))
      check k1.kind == pkRsa and k2.kind == pkRsa
      check k1.rsa.n == k2.rsa.n and k1.rsa.d == k2.rsa.d
      check k1.rsa.e == k2.rsa.e
      # Cross-check public part against openssl.
      let (pubOut, _) = execCmdEx(osslBin & " rsa -in " & dir / "rsa.pem" &
        " -pubout -outform DER", workingDir = dir)
      check pubOut.len > 0
      # Sign/verify round trip with the imported key.
      let msg = toBytes("hello tls")
      let sig = rsaAlgo.pkcs1v15Sign(k1.rsa, rsaAlgo.rhSha256, msg)
      check rsaAlgo.pkcs1v15Verify(rsaAlgo.publicKey(k1.rsa),
                                   rsaAlgo.rhSha256, msg, sig)

    test "ec sec1 pem + pkcs8 pem agree":
      let k1 = loadPrivateKeyPem(readFile(dir / "ec.pem"))
      let k2 = loadPrivateKeyPem(readFile(dir / "ec_pkcs8.pem"))
      check k1.kind == pkEc and k2.kind == pkEc
      check k1.ec.d == k2.ec.d
      check k1.ec.curve == ecdsaAlgo.P256
      # ECDH self-consistency through the imported scalar.
      let peer = ecdsaAlgo.generateKeyPair(ecdsaAlgo.P256)
      let z1 = ecdsaAlgo.ecdh(k1.ec, peer[1])
      let z2 = ecdsaAlgo.ecdh(peer[0], ecdsaAlgo.publicKeyFromPrivate(k1.ec))
      check z1 == z2

    test "ed25519 + x25519 pkcs8":
      let ek = loadPrivateKeyPem(readFile(dir / "ed.pem"))
      check ek.kind == pkEd25519
      let xk = loadPrivateKeyPem(readFile(dir / "x.pem"))
      check xk.kind == pkX25519

    test "encrypted pkcs8 rejected":
      run(dir, osslBin & " pkcs8 -topk8 -in rsa.pem -out rsa_enc.pem " &
        "-passout pass:hunter2")
      expect(ValueError):
        discard loadPrivateKeyPem(readFile(dir / "rsa_enc.pem"))

    test "garbage rejected":
      expect(ValueError):
        discard loadPrivateKeyPem("-----BEGIN PRIVATE KEY-----\nAAAA\n" &
          "-----END PRIVATE KEY-----\n")
      expect(ValueError):
        discard loadPrivateKeyPem("no blocks here")
