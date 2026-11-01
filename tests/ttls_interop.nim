# Live TLS 1.3 interop: our client handshakes openssl s_server and
# fetches an HTTP response. Requires openssl on PATH (same skip
# convention as topenssl).
import std/net
import std/os
import std/osproc
import std/strutils
import std/unittest
import std/times

import nimcypher/tls/pem
import nimcypher/tls/config
import nimcypher/tls/client
import nimcypher/tls/verify
import nimcypher/utils

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

proc run(dir, cmd: string) =
  let (outp, code) = execCmdEx(cmd, workingDir = dir)
  if code != 0:
    raise newException(OSError, "openssl failed: " & cmd & "\n" & outp)

proc recvExactly(sock: Socket, n: int): string =
  ## Read exactly n bytes (record framing needs exact reads).
  ## Raises on timeout/close; never silently consumes partial data.
  result = sock.recv(n, timeout = 5000)
  if result.len != n:
    raise newException(OSError, "short read: want " & $n & " got " &
      $result.len)

suite "tls interop vs openssl s_server":
  if osslBin == "":
    if requireOssl:
      raise newException(OSError, "openssl missing but required")
    echo "SKIP ttls_interop: openssl not on PATH"
  else:
    test "handshake + https GET":
      let dir = getTempDir() / "nimcypher_ttls_interop"
      createDir(dir)
      run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out ca.key")
      run(dir, osslBin & " req -x509 -new -key ca.key -sha256 -days 2 " &
        "-subj \"/CN=Interop Root\" -out ca.pem")
      run(dir, osslBin & " ecparam -name prime256v1 -genkey -noout -out srv.key")
      run(dir, osslBin & " req -new -key srv.key -subj \"/CN=localhost\" -out srv.csr")
      writeFile(dir / "srv.ext",
        "subjectAltName=DNS:localhost\nbasicConstraints=CA:false\n")
      run(dir, osslBin & " x509 -req -in srv.csr -CA ca.pem -CAkey ca.key " &
        "-CAcreateserial -days 2 -sha256 -extfile srv.ext -out srv.pem")

      var store = TrustStore()
      store.addDer(pemBlocks(readFile(dir / "ca.pem"))[0])
      var cfg = defaultClientConfigWithRoots(store)

      let port = Port(18443)
      var srv = startProcess(osslBin,
        args = ["s_server", "-accept", $port, "-cert", dir / "srv.pem",
                "-key", dir / "srv.key", "-tls1_3", "-www", "-naccept", "1"],
        options = {poUsePath})
      sleep(800) # let s_server bind
      try:
        var sock = newSocket()
        sock.setSockOpt(OptReuseAddr, true)
        sock.connect("127.0.0.1", port)
        var conn = newClientConn(cfg, "localhost")
        let deadline = getTime() + initDuration(seconds = 20)
        var gotHttp = false
        var sentGet = false
        var response = ""
        # Drive the handshake record by record.
        while getTime() < deadline and not conn.established and
            not conn.failed:
          let flight = conn.takeOutbox()
          if flight.len > 0:
            sock.send(toString(flight))
          let hdr = recvExactly(sock, 5)
          let reclen = (ord(hdr[3]) shl 8) or ord(hdr[4])
          if reclen > 16384 + 256:
            raise newException(OSError, "record overflow")
          conn.feed(toBytes(hdr) & toBytes(recvExactly(sock, reclen)))
        if conn.failed:
          raise newException(OSError, "client failed: " & conn.failReason)
        check conn.established
        # HTTPS exchange.
        conn.encryptApp("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        let flight = conn.takeOutbox()
        sock.send(toString(flight))
        while getTime() < deadline:
          let hdr = recvExactly(sock, 5)
          let reclen = (ord(hdr[3]) shl 8) or ord(hdr[4])
          conn.feed(toBytes(hdr) & toBytes(recvExactly(sock, reclen)))
          for b in conn.readApp(): response.add(char(b))
          if response.contains("HTTP/"):
            gotHttp = true
            break
        check gotHttp
        check conn.established
        check gotHttp
        check response.contains("HTTP/")
        conn.sendCloseNotify()
        let bye = conn.takeOutbox()
        if bye.len > 0:
          sock.send(toString(bye))
        sock.close()
      finally:
        srv.terminate()
        discard srv.waitForExit(3000)
