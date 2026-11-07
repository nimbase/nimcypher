# Chain validation + hostname tests. Hostname cases are pure unit
# tests; chain cases use openssl-generated certs (skip without openssl).
import std/os
import std/osproc
import std/unittest
import std/times

import nimcypher/tls/pem
import nimcypher/tls/x509
import nimcypher/tls/verify

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

proc run(dir, cmd: string) =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "openssl failed: " & cmd & "\n" & outp)

suite "hostname matching":
  test "exact, case, trailing dot":
    var t = TbsCertificate(sanDns: @["www.example.com"])
    check verifyHostname(Certificate(tbs: t), "www.example.com")
    check verifyHostname(Certificate(tbs: t), "WWW.EXAMPLE.COM")
    check verifyHostname(Certificate(tbs: t), "www.example.com.")
    check not verifyHostname(Certificate(tbs: t), "other.example.com")
    check not verifyHostname(Certificate(tbs: t), "sub.www.example.com")

  test "wildcard single label only":
    var t = TbsCertificate(sanDns: @["*.wild.example"])
    check verifyHostname(Certificate(tbs: t), "a.wild.example")
    check not verifyHostname(Certificate(tbs: t), "a.b.wild.example")
    check not verifyHostname(Certificate(tbs: t), "wild.example")
    check not verifyHostname(Certificate(tbs: t), "a.wild.example.com")

  test "cn fallback when no san":
    var t = TbsCertificate(subjectCn: "legacy.example.com")
    check verifyHostname(Certificate(tbs: t), "legacy.example.com")
    check not verifyHostname(Certificate(tbs: t), "x.example.com")

  test "san present ignores cn":
    var t = TbsCertificate(subjectCn: "ignore.example.com",
                           sanDns: @["real.example.com"])
    check verifyHostname(Certificate(tbs: t), "real.example.com")
    check not verifyHostname(Certificate(tbs: t), "ignore.example.com")

suite "chain validation":
  if osslBin == "":
    if requireOssl:
      raise newException(OSError, "openssl missing but required")
    echo "SKIP ttls_verify chain: openssl not on PATH"
  else:
    let dir = getTempDir() / "nimcypher_ttls_verify"
    createDir(dir)
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out root.key")
    run(dir, osslBin & " req -x509 -new -key root.key -sha256 -days 30 " &
      "-subj \"/CN=VRoot\" -out root.pem")
    # intermediate CA:true pathlen:0
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out int.key")
    run(dir, osslBin & " req -new -key int.key -subj \"/CN=VInt\" -out int.csr")
    writeFile(dir / "int.ext", "basicConstraints=critical,CA:true,pathlen:0\n" &
      "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n")
    run(dir, osslBin & " x509 -req -in int.csr -CA root.pem -CAkey root.key " &
      "-CAcreateserial -days 30 -sha256 -extfile int.ext -out int.pem")
    # leaf with SAN
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out leaf.key")
    run(dir, osslBin & " req -new -key leaf.key -subj \"/CN=service.example\" -out leaf.csr")
    writeFile(dir / "leaf.ext",
      "subjectAltName=DNS:service.example\nbasicConstraints=CA:false\n" &
      "keyUsage=digitalSignature\n" &
      "extendedKeyUsage=serverAuth\n")
    run(dir, osslBin & " x509 -req -in leaf.csr -CA int.pem -CAkey int.key " &
      "-CAcreateserial -days 30 -sha256 -extfile leaf.ext -out leaf.pem")

    let rootDer = pemBlocks(readFile(dir / "root.pem"))[0]
    let intDer = pemBlocks(readFile(dir / "int.pem"))[0]
    let leafDer = pemBlocks(readFile(dir / "leaf.pem"))[0]
    var store = TrustStore()
    store.addDer(rootDer)

    test "valid 3-level chain":
      check verifyChain(leafDer, @[intDer], store, "service.example")

    test "wrong hostname fails":
      check not verifyChain(leafDer, @[intDer], store, "evil.example")

    test "untrusted root fails":
      check not verifyChain(leafDer, @[intDer], TrustStore(),
        "service.example")

    test "missing intermediate fails":
      check not verifyChain(leafDer, @[], store, "service.example")

    test "expired leaf fails":
      check not verifyChain(leafDer, @[intDer], store, "service.example",
        now = getTime().toUnix() + 60 * 86400)
