# X.509 parse + signature verification against openssl-generated certs.
# Skips without openssl on PATH (loud fail with NIMCYPHER_REQUIRE_OPENSSL=1).
import std/os
import std/osproc
import std/strutils
import std/unittest
import std/times

import nimcypher/tls/pem
import nimcypher/tls/x509

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

proc run(dir, cmd: string): string =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "openssl failed: " & cmd & "\n" & outp)
  outp

proc setupCerts(dir: string) =
  createDir(dir)
  discard run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ca.key")
  discard run(dir, osslBin & " req -x509 -new -key ca.key -sha256 -days 2 " &
    "-subj \"/CN=Test Root CA\" -out ca.pem")
  discard run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out leaf.key")
  discard run(dir, osslBin & " req -new -key leaf.key -subj \"/CN=www.example.com\" -out leaf.csr")
  writeFile(dir / "leaf.ext",
    "subjectAltName=DNS:www.example.com,DNS:*.wild.example\nbasicConstraints=CA:false\n")
  discard run(dir, osslBin & " x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key " &
    "-CAcreateserial -days 1 -sha256 -extfile leaf.ext -out leaf.pem")
  # RSA pair for the PKCS#1 v1.5 path
  discard run(dir, osslBin & " genrsa -out rsa_ca.key 2048")
  discard run(dir, osslBin & " req -x509 -new -key rsa_ca.key -sha256 -days 2 " &
    "-subj \"/CN=RSA Root\" -out rsa_ca.pem")
  discard run(dir, osslBin & " genrsa -out rsa_leaf.key 2048")
  discard run(dir, osslBin & " req -new -key rsa_leaf.key -subj \"/CN=rsa.example.com\" -out rsa_leaf.csr")
  writeFile(dir / "rsa_leaf.ext", "basicConstraints=CA:false\n")
  discard run(dir, osslBin & " x509 -req -in rsa_leaf.csr -CA rsa_ca.pem " &
    "-CAkey rsa_ca.key -CAcreateserial -days 1 -sha256 -extfile rsa_leaf.ext -out rsa_leaf.pem")

suite "x509 parse + verify":
  if osslBin == "":
    if requireOssl:
      raise newException(OSError, "openssl missing but required")
    echo "SKIP ttls_x509: openssl not on PATH"
  else:
    let dir = getTempDir() / "nimcypher_ttls_x509"
    setupCerts(dir)
    let caDer = pemBlocks(readFile(dir / "ca.pem"))[0]
    let leafDer = pemBlocks(readFile(dir / "leaf.pem"))[0]
    let rsaCaDer = pemBlocks(readFile(dir / "rsa_ca.pem"))[0]
    let rsaLeafDer = pemBlocks(readFile(dir / "rsa_leaf.pem"))[0]

    test "ecdsa cert fields parse":
      let ca = parseCertificate(caDer)
      check ca.tbs.version == 3
      check ca.tbs.issuerCn == "Test Root CA"
      check ca.tbs.subjectCn == "Test Root CA"
      check ca.tbs.isCa
      check ca.tbs.spki.kind == skEc
      let leaf = parseCertificate(leafDer)
      check leaf.tbs.subjectCn == "www.example.com"
      check leaf.tbs.issuerCn == "Test Root CA"
      check not leaf.tbs.isCa
      check leaf.tbs.sanDns == @["www.example.com", "*.wild.example"]
      check leaf.tbs.notBefore <= getTime().toUnix()
      check leaf.tbs.notAfter > getTime().toUnix()

    test "ecdsa signature verifies, tamper fails":
      let ca = parseCertificate(caDer)
      let leaf = parseCertificate(leafDer)
      check verifyCertSignature(leaf, ca.tbs.spki)
      check verifyCertSignature(ca, ca.tbs.spki) # self-signed root
      var bad = leaf
      bad.signature[0] = bad.signature[0] xor 1
      check not verifyCertSignature(bad, ca.tbs.spki)
      check not verifyCertSignature(leaf, leaf.tbs.spki) # wrong key

    test "rsa cert fields + pkcs1v15 verify":
      let ca = parseCertificate(rsaCaDer)
      let leaf = parseCertificate(rsaLeafDer)
      check ca.tbs.spki.kind == skRsa
      check leaf.tbs.subjectCn == "rsa.example.com"
      check verifyCertSignature(leaf, ca.tbs.spki)
      check verifyCertSignature(ca, ca.tbs.spki)
      var bad = leaf
      bad.tbs.raw[20] = bad.tbs.raw[20] xor 1
      check not verifyCertSignature(bad, ca.tbs.spki)
