# In-process client<->server loopback: full handshakes over a virtual
# wire, then application data both ways. Uses openssl-generated
# cert+key (same skip convention as the other live tests).
import std/os
import std/osproc
import std/unittest
import std/times

import nimcypher/tls/pem
import nimcypher/tls/config
import nimcypher/tls/keys
import nimcypher/tls/client
import nimcypher/tls/server
import nimcypher/tls/verify
import nimcypher/tls/enums
import nimcypher/utils

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

proc run(dir, cmd: string) =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "openssl failed: " & cmd & "\n" & outp)

proc pump(c: var TlsClientConn, s: var TlsServerConn, maxRounds = 50) =
  var i = 0
  while i < maxRounds and not ((c.established and s.established) or
      c.failed or s.failed):
    let cf = c.takeOutbox()
    if cf.len > 0: s.feed(cf)
    let sf = s.takeOutbox()
    if sf.len > 0: c.feed(sf)
    inc i

suite "tls loopback":
  if osslBin == "":
    if requireOssl:
      raise newException(OSError, "openssl missing but required")
    echo "SKIP ttls_loopback: openssl not on PATH"
  else:
    let dir = getTempDir() / "nimcypher_ttls_loopback"
    createDir(dir)
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ca.key")
    run(dir, osslBin & " req -x509 -new -key ca.key -sha256 -days 2 " &
      "-subj \"/CN=Loop Root\" -out ca.pem")
    run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out srv.key")
    run(dir, osslBin & " req -new -key srv.key -subj \"/CN=localhost\" -out srv.csr")
    writeFile(dir / "srv.ext",
      "subjectAltName=DNS:localhost\nbasicConstraints=CA:false\n")
    run(dir, osslBin & " x509 -req -in srv.csr -CA ca.pem -CAkey ca.key " &
      "-CAcreateserial -days 2 -sha256 -extfile srv.ext -out srv.pem")
    run(dir, osslBin & " genrsa -out rsa_srv.key 2048")
    run(dir, osslBin & " req -new -key rsa_srv.key -subj \"/CN=localhost\" -out rsa_srv.csr")
    writeFile(dir / "rsa_srv.ext",
      "subjectAltName=DNS:localhost\nbasicConstraints=CA:false\n")
    run(dir, osslBin & " x509 -req -in rsa_srv.csr -CA ca.pem -CAkey ca.key " &
      "-CAcreateserial -days 2 -sha256 -extfile rsa_srv.ext -out rsa_srv.pem")

    var store = TrustStore()
    store.addDer(pemBlocks(readFile(dir / "ca.pem"))[0])

    test "ecdsa loopback + app data both ways":
      let chainPem = readFile(dir / "srv.pem")
      let key = loadPrivateKeyPem(readFile(dir / "srv.key"))
      var s = newServerConn(defaultServerConfig(), chainPem, key)
      var c = newClientConn(defaultClientConfigWithRoots(store), "localhost")
      pump(c, s)
      check not c.failed
      check not s.failed
      if c.failed: echo "client: ", c.failReason
      if s.failed: echo "server: ", s.failReason
      check c.established and s.established
      check c.alpnSelected == "h2" # both default to h2 first
      c.encryptApp("ping")
      s.feed(c.takeOutbox())
      check s.readApp() == toBytes("ping")
      s.encryptApp("pong")
      c.feed(s.takeOutbox())
      check c.readApp() == toBytes("pong")
      c.sendCloseNotify()
      s.feed(c.takeOutbox())
      check s.state == ssClosed

    test "rsa loopback (pss CertificateVerify)":
      let chainPem = readFile(dir / "rsa_srv.pem")
      let key = loadPrivateKeyPem(readFile(dir / "rsa_srv.key"))
      var s = newServerConn(defaultServerConfig(), chainPem, key)
      var c = newClientConn(defaultClientConfigWithRoots(store), "localhost")
      pump(c, s)
      if c.failed: echo "rsa client: ", c.failReason
      if s.failed: echo "rsa server: ", s.failReason
      check not c.failed
      check not s.failed
      check c.established and s.established
      s.encryptApp("secure")
      c.feed(s.takeOutbox())
      check c.readApp() == toBytes("secure")

    test "hrr group switch loopback":
      # Client shares x25519 only; server only speaks P-256.
      let chainPem = readFile(dir / "srv.pem")
      let key = loadPrivateKeyPem(readFile(dir / "srv.key"))
      var scfg = defaultServerConfig()
      scfg.groups = @[ngSecp256r1]
      var s = newServerConn(scfg, chainPem, key)
      var ccfg = defaultClientConfigWithRoots(store)
      ccfg.groups = @[ngX25519, ngSecp256r1]
      var c = newClientConn(ccfg, "localhost")
      pump(c, s)
      if c.failed: echo "hrr client: ", c.failReason
      if s.failed: echo "hrr server: ", s.failReason
      check not c.failed
      check not s.failed
      check c.established and s.established

    test "key mismatch rejected at construction":
      let chainPem = readFile(dir / "srv.pem") # ec leaf
      let wrongKey = loadPrivateKeyPem(readFile(dir / "rsa_srv.key"))
      expect(ValueError):
        discard newServerConn(defaultServerConfig(), chainPem, wrongKey)
