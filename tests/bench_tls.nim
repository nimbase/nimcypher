# TLS benchmark: nimcypher vs OpenSSL, both driven at Nim level.
#
# - Handshake rate: full TLS 1.3 handshakes over loopback TCP, nimcypher
#   (TlsClientConn/TlsServerConn over std/net) vs OpenSSL (std/net ssl,
#   same binary, server in a thread). In-process loopback too (no I/O).
# - Bulk record throughput (16 KiB messages): nimcypher seal/open vs
#   OpenSSL EVP AES-GCM / ChaCha20-Poly1305 via direct FFI below.
# - Component ops: nimcypher ECDHE/ECDSA/RSA/key-schedule/chain-verify.
#
# Requires the openssl CLI only for one-time test-cert provisioning
# (same convention as the live tests) and -d:ssl at build time.
#
# Run: nim c -r -d:ssl -d:danger --opt:speed --threads:on tests/bench_tls.nim
import std/monotimes
import std/times
import std/strformat
import std/os
import std/osproc
import std/options
import std/net

import nimcypher/utils
import nimcypher/tls/enums
import nimcypher/tls/aead
import nimcypher/tls/record
import nimcypher/tls/handshake
import nimcypher/tls/key_schedule
import nimcypher/tls/pem
import nimcypher/tls/x509
import nimcypher/tls/verify
import nimcypher/tls/config
import nimcypher/tls/keys
import nimcypher/tls/client
import nimcypher/tls/server
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/x25519 as x25519Algo

import std/openssl

# --- OpenSSL FFI (libcrypto, same dylib Nim's net ssl uses) ---

type
  EVP_CIPHER = ptr object
  EVP_CIPHER_CTX = ptr object

{.push dynlib: DLLUtilName, cdecl, importc.}
proc EVP_CIPHER_CTX_new(): EVP_CIPHER_CTX
proc EVP_CIPHER_CTX_free(c: EVP_CIPHER_CTX)
proc EVP_aes_128_gcm(): EVP_CIPHER
proc EVP_aes_256_gcm(): EVP_CIPHER
proc EVP_chacha20_poly1305(): EVP_CIPHER
proc EVP_EncryptInit_ex(c: EVP_CIPHER_CTX, typ: EVP_CIPHER,
                        impl, key, iv: pointer): cint
proc EVP_EncryptUpdate(c: EVP_CIPHER_CTX, outd: pointer, outl: ptr cint,
                       ind: pointer, inl: cint): cint
proc EVP_EncryptFinal_ex(c: EVP_CIPHER_CTX, outd: pointer,
                         outl: ptr cint): cint
proc EVP_DecryptInit_ex(c: EVP_CIPHER_CTX, typ: EVP_CIPHER,
                        impl, key, iv: pointer): cint
proc EVP_DecryptUpdate(c: EVP_CIPHER_CTX, outd: pointer, outl: ptr cint,
                       ind: pointer, inl: cint): cint
proc EVP_DecryptFinal_ex(c: EVP_CIPHER_CTX, outd: pointer,
                         outl: ptr cint): cint
proc EVP_CIPHER_CTX_ctrl(c: EVP_CIPHER_CTX, typ: cint, arg: cint,
                         p: pointer): cint
{.pop.}

const
  EVP_CTRL_AEAD_GET_TAG = 0x10
  EVP_CTRL_AEAD_SET_TAG = 0x11

# --- harness ---

var sink: byte

proc timeIt(iters: int, f: proc() {.closure.}): float =
  f()
  let start = getMonoTime()
  for _ in 0 ..< iters:
    f()
  result = (getMonoTime() - start).inNanoseconds.float / 1e9

proc msPerOp(total: float, iters: int): string =
  fmt"{total / iters.float * 1000:.2f}ms/op ({iters.float / total:.1f}/s)"

proc mbPerSec(total: float, bytes: int): string =
  fmt"{bytes.float / total / 1e6:.1f} MB/s"

proc run(dir, cmd: string) =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "setup failed: " & cmd & "\n" & outp)

proc recvExactly(sock: Socket, n: int): string =
  result = sock.recv(n, timeout = 15000)
  if result.len != n:
    raise newException(OSError, "short read")

# Server threads are self-contained (thread-local heaps under ARC):
# each rebuilds everything from files, no shared GC state.
const
  BenchSubdir = "nimcypher_bench_tls"
  PortN = Port(18611)
  PortO = Port(18612)
  TcpIters = 20

proc nimTlsSrvProc() {.thread.} =
  {.cast(gcsafe).}:
    let dir = getTempDir() / BenchSubdir
    let chain = readFile(dir / "ec.pem")
    let key = loadPrivateKeyPem(readFile(dir / "ec.key"))
    var store = TrustStore()
    store.addDer(pemBlocks(readFile(dir / "ca.pem"))[0])
    var srv = newSocket()
    srv.setSockOpt(OptReuseAddr, true)
    srv.bindAddr(PortN)
    srv.listen()
    for _ in 0 ..< TcpIters + 1: # +1 for timeIt warmup
      var cli: Socket
      var a = ""
      srv.acceptAddr(cli, a)
      var s = newServerConn(defaultServerConfig(), chain, key)
      while not s.established and not s.failed:
        let hdr = recvExactly(cli, 5)
        let n = (ord(hdr[3]) shl 8) or ord(hdr[4])
        s.feed(toBytes(hdr) & toBytes(recvExactly(cli, n)))
        let fl = s.takeOutbox()
        if fl.len > 0: cli.send(toString(fl))
      doAssert s.established
      # Read the client's ping, echo it back, then consume close_notify.
      let ahdr = recvExactly(cli, 5)
      let an = (ord(ahdr[3]) shl 8) or ord(ahdr[4])
      s.feed(toBytes(ahdr) & toBytes(recvExactly(cli, an)))
      let app = s.readApp()
      doAssert app == toBytes("ping")
      s.encryptApp(app)
      let fl2 = s.takeOutbox()
      if fl2.len > 0: cli.send(toString(fl2))
      # Client sends close_notify then closes; tolerate a torn-down
      # socket here (RST on unread data) - the echo already proved
      # bidirectional traffic.
      try:
        let hdr = recvExactly(cli, 5)
        let n = (ord(hdr[3]) shl 8) or ord(hdr[4])
        discard recvExactly(cli, n)
      except OSError:
        discard
      cli.close()
    srv.close()

proc osslSrvProc() {.thread.} =
  {.cast(gcsafe).}:
    let dir = getTempDir() / BenchSubdir
    var ctx = newContext(certFile = dir / "ec.pem",
                         keyFile = dir / "ec.key",
                         verifyMode = CVerifyNone)
    var srv = newSocket()
    ctx.wrapSocket(srv)
    srv.setSockOpt(OptReuseAddr, true)
    srv.bindAddr(PortO)
    srv.listen()
    for _ in 0 ..< TcpIters + 1: # +1 for timeIt warmup
      var cli: Socket
      var a = ""
      srv.acceptAddr(cli, a)
      let line = cli.recvLine()
      cli.send("pong\n")
      cli.close()
    srv.close()

# --- OpenSSL EVP one-shot helpers ---

proc osslSeal(cipher: EVP_CIPHER, key, iv, pt, ad: openArray[byte]): seq[byte] =
  let ctx = EVP_CIPHER_CTX_new()
  if ctx == nil: raise newException(OSError, "EVP ctx alloc failed")
  defer: EVP_CIPHER_CTX_free(ctx)
  if EVP_EncryptInit_ex(ctx, cipher, nil,
      if key.len > 0: unsafeAddr key[0] else: nil,
      if iv.len > 0: unsafeAddr iv[0] else: nil) != 1:
    raise newException(OSError, "EncryptInit failed")
  var outl: cint
  var ct = newSeq[byte](pt.len + 16)
  if ad.len > 0:
    if EVP_EncryptUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                         ad.len.cint) != 1:
      raise newException(OSError, "EncryptUpdate(ad) failed")
  if pt.len > 0:
    if EVP_EncryptUpdate(ctx, addr ct[0], addr outl, unsafeAddr pt[0],
                         pt.len.cint) != 1:
      raise newException(OSError, "EncryptUpdate failed")
  var n1 = outl.int
  if EVP_EncryptFinal_ex(ctx, addr ct[n1], addr outl) != 1:
    raise newException(OSError, "EncryptFinal failed")
  n1 += outl.int
  var tag: array[16, byte]
  if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                         addr tag[0]) != 1:
    raise newException(OSError, "GET_TAG failed")
  result = ct[0 ..< n1] & @(toOpenArray(tag, 0, 15))

proc osslOpen(cipher: EVP_CIPHER, key, iv, ct, tag,
              ad: openArray[byte]): seq[byte] =
  let ctx = EVP_CIPHER_CTX_new()
  if ctx == nil: raise newException(OSError, "EVP ctx alloc failed")
  defer: EVP_CIPHER_CTX_free(ctx)
  if EVP_DecryptInit_ex(ctx, cipher, nil,
      if key.len > 0: unsafeAddr key[0] else: nil,
      if iv.len > 0: unsafeAddr iv[0] else: nil) != 1:
    raise newException(OSError, "DecryptInit failed")
  var outl: cint
  var pt = newSeq[byte](ct.len + 16)
  if ad.len > 0:
    if EVP_DecryptUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                         ad.len.cint) != 1:
      raise newException(OSError, "DecryptUpdate(ad) failed")
  if ct.len > 0:
    if EVP_DecryptUpdate(ctx, addr pt[0], addr outl, unsafeAddr ct[0],
                         ct.len.cint) != 1:
      raise newException(OSError, "DecryptUpdate failed")
  var n1 = outl.int
  if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag.len.cint,
                         unsafeAddr tag[0]) != 1:
    raise newException(OSError, "SET_TAG failed")
  if EVP_DecryptFinal_ex(ctx, addr pt[n1], addr outl) != 1:
    raise newException(OSError, "tag verify failed")
  n1 += outl.int
  result = pt[0 ..< n1]

when isMainModule:
  let osslBin = findExe("openssl")
  if osslBin == "":
    quit "openssl CLI required for cert provisioning"
  let dir = getTempDir() / BenchSubdir
  createDir(dir)
  run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ca.key")
  run(dir, osslBin & " req -x509 -new -key ca.key -sha256 -days 2 " &
    "-subj \"/CN=Bench Root\" -out ca.pem")
  run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ec.key")
  run(dir, osslBin & " req -new -key ec.key -subj \"/CN=localhost\" -out ec.csr")
  writeFile(dir / "ec.ext", "subjectAltName=DNS:localhost\n")
  run(dir, osslBin & " x509 -req -in ec.csr -CA ca.pem -CAkey ca.key " &
    "-CAcreateserial -days 2 -sha256 -extfile ec.ext -out ec.pem")
  run(dir, osslBin & " genrsa -out rsa.key 2048")
  run(dir, osslBin & " req -new -key rsa.key -subj \"/CN=localhost\" -out rsa.csr")
  writeFile(dir / "rsa.ext", "subjectAltName=DNS:localhost\n")
  run(dir, osslBin & " x509 -req -in rsa.csr -CA ca.pem -CAkey ca.key " &
    "-CAcreateserial -days 2 -sha256 -extfile rsa.ext -out rsa.pem")

  var store = TrustStore()
  store.addDer(pemBlocks(readFile(dir / "ca.pem"))[0])
  let ecKey = loadPrivateKeyPem(readFile(dir / "ec.key"))
  let rsaKey = loadPrivateKeyPem(readFile(dir / "rsa.key"))
  let ecChain = readFile(dir / "ec.pem")
  let rsaChain = readFile(dir / "rsa.pem")

  echo "# TLS benchmark: nimcypher vs OpenSSL (both at Nim level)"
  echo ""
  echo "AMD Ryzen 5 5500, `-d:danger --opt:speed`, OpenSSL 3.6.3."
  echo ""

  # ---- A. in-process loopback handshakes ----
  echo "## A. full handshake, in-process loopback (no sockets)"
  echo ""
  echo "| handshake | nimcypher hs/s | ms/hs |"
  echo "| --- | ---: | ---: |"
  for (name, chain, key, iters) in
      [("ECDSA P-256", ecChain, ecKey, 30), ("RSA-2048", rsaChain, rsaKey, 8)]:
    let t = timeIt(iters, proc() =
      var s = newServerConn(defaultServerConfig(), chain, key)
      var c = newClientConn(defaultClientConfigWithRoots(store), "localhost")
      var i = 0
      while i < 60 and not (c.established and s.established) and
          not c.failed and not s.failed:
        let cf = c.takeOutbox()
        if cf.len > 0: s.feed(cf)
        let sf = s.takeOutbox()
        if sf.len > 0: c.feed(sf)
        inc i
      doAssert c.established and s.established
      sink = sink xor byte(ord(c.established)))
    echo fmt"| {name} | {iters.float / t:.1f} | {t / iters.float * 1000:.2f} |"
  echo ""

  # ---- B. handshake rate over loopback TCP ----
  echo "## B. handshake + 1 RTT app echo over loopback TCP"
  echo ""
  echo "| stack | hs/s | ms/hs |"
  echo "| --- | ---: | ---: |"

  block nimTlsTcp:
    var thr: Thread[void]
    createThread(thr, nimTlsSrvProc)
    sleep(500)
    let t = timeIt(TcpIters, proc() =
      var sock = newSocket()
      sock.connect("127.0.0.1", PortN)
      var c = newClientConn(defaultClientConfigWithRoots(store), "localhost")
      while not c.established and not c.failed:
        let fl = c.takeOutbox()
        if fl.len > 0: sock.send(toString(fl))
        let hdr = recvExactly(sock, 5)
        let n = (ord(hdr[3]) shl 8) or ord(hdr[4])
        c.feed(toBytes(hdr) & toBytes(recvExactly(sock, n)))
      doAssert c.established
      c.encryptApp("ping")
      let fl = c.takeOutbox()
      sock.send(toString(fl))
      let hdr = recvExactly(sock, 5)
      let n = (ord(hdr[3]) shl 8) or ord(hdr[4])
      c.feed(toBytes(hdr) & toBytes(recvExactly(sock, n)))
      doAssert c.readApp() == toBytes("ping")
      c.sendCloseNotify()
      let bye = c.takeOutbox()
      if bye.len > 0: sock.send(toString(bye))
      sleep(50) # let the server consume close_notify before FIN/RST
      sock.close()
      sink = sink xor byte(ord(c.established)))
    joinThread(thr)
    echo fmt"| nimcypher TLS 1.3 | {TcpIters.float / t:.1f} | {t / TcpIters.float * 1000:.2f} |"

  block osslTcp:
    var thr: Thread[void]
    createThread(thr, osslSrvProc)
    sleep(500)
    let t = timeIt(TcpIters, proc() =
      var ctx = newContext(verifyMode = CVerifyNone)
      var s = newSocket()
      ctx.wrapSocket(s)
      s.connect("127.0.0.1", PortO)
      s.send("ping\n")
      let back = s.recvLine()
      doAssert back == "pong"
      sink = sink xor byte(back.len)
      s.close())
    joinThread(thr)
    echo fmt"| OpenSSL TLS 1.3 (net ssl) | {TcpIters.float / t:.1f} | {t / TcpIters.float * 1000:.2f} |"
  echo ""

  # ---- C. bulk record throughput, 16 KiB ----
  echo "## C. bulk record throughput, 16 KiB messages"
  echo ""
  echo "| suite | nimcypher seal | nimcypher open | OpenSSL seal | OpenSSL open |"
  echo "| --- | ---: | ---: | ---: | ---: |"
  var big = newSeq[byte](16384)
  for i in 0 ..< big.len: big[i] = byte(i and 0xFF)
  let ciphers = [("AES-128-GCM", TlsAes128GcmSha256, EVP_aes_128_gcm(), 16),
                 ("AES-256-GCM", TlsAes256GcmSha384, EVP_aes_256_gcm(), 32),
                 ("ChaCha20-Poly1305", TlsChacha20Poly1305Sha256,
                  EVP_chacha20_poly1305(), 32)]
  for (name, suite, evp, keyLen) in ciphers:
    var k: seq[byte] = newSeq[byte](keyLen)
    for i in 0 ..< keyLen: k[i] = byte i
    var n: seq[byte] = newSeq[byte](12)
    for i in 0 ..< 12: n[i] = byte (i + 1)
    let ad = @[byte 0x17, 0x03, 0x03, 0x40, 0x00]
    let iters = 300
    let (ct0, tag0) = tlsSeal(suite, k, n, big, ad)
    let tSeal = timeIt(iters, proc() =
      let (ct, tag) = tlsSeal(suite, k, n, big, ad)
      sink = sink xor ct[0] xor tag[0])
    let tOpen = timeIt(iters, proc() =
      let pt = tlsOpen(suite, k, n, ct0, tag0, ad)
      sink = sink xor pt.get()[0])
    let tOsslSeal = timeIt(iters, proc() =
      let outp = osslSeal(evp, k, n, big, ad)
      sink = sink xor outp[0])
    let ot = osslSeal(evp, k, n, big, ad)
    let osslCt = ot[0 ..< ot.len - 16]
    let osslTag = ot[ot.len - 16 .. ^1]
    let tOsslOpen = timeIt(iters, proc() =
      let pt = osslOpen(evp, k, n, osslCt, osslTag, ad)
      sink = sink xor pt[0])
    let bytes = iters * big.len
    echo fmt"| {name} | {mbPerSec(tSeal, bytes)} | {mbPerSec(tOpen, bytes)} | " &
      fmt"{mbPerSec(tOsslSeal, bytes)} | {mbPerSec(tOsslOpen, bytes)} |"
  echo ""

  # ---- D. nimcypher component ops ----
  echo "## D. nimcypher handshake component ops"
  echo ""
  echo "| op | ms/op | rate |"
  echo "| --- | ---: | ---: |"
  block:
    var sk = randomBytes[32]()
    let pk = x25519Algo.x25519PublicKey(sk)
    let t = timeIt(200, proc() =
      let z = x25519Algo.x25519(sk, pk)
      sink = sink xor z[0])
    echo fmt"| ECDHE X25519 | {msPerOp(t, 200)} |"
  block:
    let (priv, pub) = ecdsaAlgo.generateKeyPair(ecdsaAlgo.P256)
    let t = timeIt(50, proc() =
      let z = ecdsaAlgo.ecdh(priv, pub)
      sink = sink xor z[0])
    echo fmt"| ECDH P-256 | {msPerOp(t, 50)} |"
  block:
    let (priv, pub) = ecdsaAlgo.generateKeyPair(ecdsaAlgo.P256)
    let msg = toBytes("bench")
    let sig = ecdsaAlgo.sign(priv, msg)
    let tS = timeIt(20, proc() =
      let s = ecdsaAlgo.sign(priv, msg)
      sink = sink xor s[0])
    let tV = timeIt(20, proc() =
      let ok = ecdsaAlgo.verify(pub, msg, sig)
      sink = sink xor byte(ord(ok)))
    echo fmt"| ECDSA P-256 sign | {msPerOp(tS, 20)} |"
    echo fmt"| ECDSA P-256 verify | {msPerOp(tV, 20)} |"
  block:
    let msg = toBytes("bench")
    let sig = rsaAlgo.pssSign(rsaKey.rsa, rsaAlgo.rhSha256, msg)
    let tS = timeIt(3, proc() =
      let s = rsaAlgo.pssSign(rsaKey.rsa, rsaAlgo.rhSha256, msg)
      sink = sink xor s[0])
    let tV = timeIt(30, proc() =
      let ok = rsaAlgo.pssVerify(rsaAlgo.publicKey(rsaKey.rsa),
                                 rsaAlgo.rhSha256, msg, sig)
      sink = sink xor byte(ord(ok)))
    echo fmt"| RSA-2048 PSS sign | {msPerOp(tS, 3)} |"
    echo fmt"| RSA-2048 PSS verify | {msPerOp(tV, 30)} |"
  block:
    let h = thSha256
    let es = earlySecretNoPsk(h)
    let hs = toHandshakeSecret(h, es, big[0 ..< 32])
    let th = hashData(h, big)
    let t = timeIt(200, proc() =
      let (a, b) = handshakeTrafficSecrets(h, hs, th)
      sink = sink xor a[0] xor b[0])
    echo fmt"| key schedule hs secrets | {msPerOp(t, 200)} |"
  block:
    let leaf = pemBlocks(readFile(dir / "ec.pem"))[0]
    let t = timeIt(20, proc() =
      let ok = verifyChain(leaf, @[], store, "localhost")
      sink = sink xor byte(ord(ok)))
    echo fmt"| chain verify (leaf+root) | {msPerOp(t, 20)} |"
  echo ""
  echo fmt"checksum: {sink}"
