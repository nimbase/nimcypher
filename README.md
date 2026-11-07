<p align="center">
  NimCypher &bullet; Port of Monocypher in Nim + high-level API and extensions
</p>

<p align="center">
  <code>nimble install nimcypher</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/nimcypher/">API reference</a><br>
  <img src="https://github.com/nimbase/nimcypher/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/nimcypher/workflows/docs/badge.svg" alt="Github Actions">
</p>


## About

NimCypher is a **pure-Nim cryptographic library** that started as a faithful port of
[Monocypher](https://monocypher.org/) 4.0.3 and has grown beyond it with the addition
of `AES-128`/`192`/`256` block cipher and `AES-GCM` authenticated encryption, the full `SHA-2`
family (`SHA-224`/`256`/`384`/`512`/`512-224`/`512-256`) plus raw `SHA-1`, `HMAC-SHA-1`
and `HKDF-SHA-256`, legacy `MD5`
and `HMAC-MD5` for interop, and the non-cryptographic `xxHash` family (`XXH32`,
`XXH64`, `XXH3_64`, `XXH128`) for checksums, and asymmetric
primitives: RSA (PKCS#1 v1.5, PSS, OAEP) and ECDSA/ECDH over P-256/P-384/P-521 and
secp256k1. It has **zero C dependency** and no runtime dependencies beyond the Nim
standard library, so it is easy to deploy and easy to audit.

It ships two layers:

- **A high-level, easy-to-remember API** (`import nimcypher`) for the common tasks:
  AES-GCM sealing, hashing, authenticated encryption and sealing, X25519 and ECDH
  key exchange, EdDSA and ECDSA signatures, RSA signing and encryption, and
  password hashing.
- **The low-level primitives** (`nimcypher/algos/...`) for fine-grained control, exposing
  the full surface with an idiomatic Nim style: `openArray[byte]` in,
  `seq[byte]` / `array[N, byte]` out, contexts as objects with `init` / `update` / `final`,
  and `Option` / `bool` where an operation can fail.

Every primitive is cross-checked byte-for-byte against the reference C Monocypher
implementation and the NIST test-vector suite.

> [!NOTE]
> This is an ambitious, experimental community project written in pure Nim with
> heavy LLM assistance. APIs may still change, and security-critical uses deserve
> independent review. Contributions are welcome: bug reports, test vectors,
> benchmarks, and ports.


## Key features

High-level API (`import nimcypher`):
- AES-GCM sealing with random nonces, plus AES block encryption in common modes
- Authenticated encryption and sealing with XChaCha20-Poly1305, including streaming
- Hashing with BLAKE2b and the full SHA-2 family, SHA-1, HMAC variants, and HKDF key derivation
- Legacy `MD5` / `HMAC-MD5` for interop and `xxHash` (`XXH32`/`XXH64`/`XXH3`) checksums
- Argon2id password hashing, verification, and key derivation
- Key exchange with X25519 and ECDH over standard curves
- Signatures: EdDSA, deterministic ECDSA, and RSA PKCS#1 v1.5 plus PSS
- Asymmetric encryption with RSA-OAEP (legacy PKCS#1 v1.5 padding also available)
- RSA and elliptic-curve key generation, secret wiping, constant-time comparison,
  hex helpers

Low-level primitives (`nimcypher/algos/...`):
- AES block cipher and AES-GCM with streaming support, checked against NIST vectors
- BLAKE2b, full SHA-2 plus SHA-1, HMAC, and HKDF building blocks
- `hashes/md5` (RFC 1321, HMAC-MD5) and `hashes/xxhash` (`XXH32`/`XXH64`/`XXH3_64`/`XXH128`)
- Argon2 password hashing in all three variants
- X25519 and ECDH key exchange, EdDSA and ECDSA signatures
- RSA signing, encryption, and key generation on an internal Montgomery engine
- BigInt helpers: byte conversion, primality testing, and random prime generation
- ChaCha20 stream ciphers, Poly1305, and Elligator 2 mappings


## Examples

### AES-GCM authenticated encryption (new in 0.2)

AES-256-GCM for authenticated encryption with random nonces:

```nim
import nimcypher/aes
import nimcypher/utils

let key = randomBytes[32]()
let sealed = gcmSeal(toBytes("attack at dawn"), key)
let plaintext = gcmOpen(sealed, key)
assert plaintext == toBytes("attack at dawn")
```

### AES block modes

```nim
import nimcypher/aes
import nimcypher/utils

let key = randomBytes[16]()
let iv  = randomBytes[16]()

let ct  = aesCbcEncrypt(key, iv, toBytes("secret message"))
let pt  = aesCbcDecrypt(key, iv, ct)
assert pt == toBytes("secret message")

let ctr = aesCtrCrypt(key, iv, toBytes("stream mode"))
let pt2 = aesCtrCrypt(key, iv, ctr)
assert pt2 == toBytes("stream mode")
```

### Password hashing and verification

Argon2id password hashing for storage, verification, and key derivation:

```nim
import nimcypher/password
import nimcypher/utils

let stored = hashPassword("hunter2")
assert verifyPassword("hunter2", stored)

let salt  = generateSalt()
let key   = deriveKeyFromPassword("hunter2", salt)  # Secret[Key32]
assert key.data.len == 32
```

### AEAD encryption and decryption

Authenticated encryption with XChaCha20-Poly1305. Two parties derive the same
shared secret from their passwords and exchange sealed messages:

```nim
import nimcypher/encrypt
import nimcypher/password
import nimcypher/utils

let (aliceSK, alicePK) = keyPairFromPassword("alice-passphrase", generateSalt())
let (bobSK, bobPK)     = keyPairFromPassword("bob-passphrase", generateSalt())
assert alicePK != bobPK

let aliceShared = sharedSecret(aliceSK.data, bobPK)
let bobShared   = sharedSecret(bobSK.data, alicePK)
assert aliceShared == bobShared

let msg    = "Hi Bob, this is Alice."
let sealed = seal(msg, aliceShared.data)
let opened = unseal(sealed, bobShared.data)
assert opened == toBytes(msg)
```

`decrypt` / `unseal` / `aeadStreamRead` raise `ValueError` when the MAC does not
verify, so a failed authentication never yields plaintext.

### AEAD streaming

Encrypt and decrypt a message in chunks with the streaming AEAD API:

```nim
import nimcypher/encrypt
import nimcypher/utils

let key   = randomBytes[32]()
let nonce = randomBytes[24]()

let message = "Hello, this is a test of AEAD streaming!"
var stream = aeadStreamInitX(key, nonce)                # also initDjb / initIetf
let (cipher1, mac1) = aeadStreamWrite(stream, toBytes(message[0 ..< 16]))
let (cipher2, mac2) = aeadStreamWrite(stream, toBytes(message[16 ..^ 1]))

var decStream = aeadStreamInitX(key, nonce)
let plain1 = aeadStreamRead(decStream, cipher1, mac1)
let plain2 = aeadStreamRead(decStream, cipher2, mac2)
assert plain1 & plain2 == toBytes(message)
```

### Hashing: BLAKE2b, full SHA-2, SHA-1, HMAC, HKDF, MD5, xxHash

```nim
import nimcypher/hash
import nimcypher/utils

let digest = blake(toBytes("hello world"))              # 32-byte BLAKE2b digest
let mac    = blakeKeyed(toBytes("msg"), toBytes("key")) # keyed (MAC)
let sha    = sha512Hex("hello world")                   # hex string
let sha2   = sha256Hex("hello world")                   # 32-byte SHA-256
let sha4   = sha384Hex("hello world")                   # 48-byte SHA-384
let sha224d = sha224Hex("hello world")                  # 28-byte SHA-224
let sha5224 = sha512_224Hex("hello world")              # 28-byte SHA-512/224
let sha5256 = sha512_256Hex("hello world")              # 32-byte SHA-512/256
let sha1d  = sha1Hex("hello world")                     # 20-byte SHA-1 (legacy only)
let hmac   = sha512Hmac(toBytes("key"), toBytes("msg"))
let hmac2  = sha256Hmac(toBytes("key"), toBytes("msg")) # 32-byte HMAC-SHA-256
let hmac1  = sha1Hmac(toBytes("key"), toBytes("msg"))   # 20-byte HMAC-SHA-1 (RFC 2202)
let okm    = hkdfSha512(toBytes("ikm"), @[], toBytes("info"), 32)
let okm2   = hkdfSha256(toBytes("ikm"), @[], toBytes("info"), 32)
assert okm.len == 32 and okm2.len == 32

var st = initSha256()               # streaming SHA-256 (also initSha512/initSha384,
st.update(toBytes("hello "))        # initSha224/initSha512_224/initSha512_256/initSha1)
st.update(toBytes("world"))
assert st.finish() == sha256(toBytes("hello world"))
```

Legacy `MD5` (broken, interop only) and non-cryptographic `xxHash`
(checksums only) live in the same module, with streaming support and
low-level access under `nimcypher/hashes/md5` and `nimcypher/hashes/xxhash`:

```nim
import nimcypher/hash
import nimcypher/utils

assert md5Hex("abc") == "900150983CD24FB0D6963F7D28E17F72"
assert md5HmacHex("Jefe", "what do ya want for nothing?") ==
  "750C783E6AB0B503EAA86E310A5DB738"

var m = initMd5()                   # streaming MD5 (also initMd5Hmac)
m.update(toBytes("a"))
m.update(toBytes("bc"))
assert m.finishHex() == md5Hex("abc")

assert xxh32Hex("abc") == "32D153FF"            # seeded 32-bit checksum
assert xxh64Hex("abc") == "44BC2CF5AD770999"    # seeded 64-bit checksum
assert xxh3_64bitsHex("abc") == "78AF5F94892F3950"
assert xxh128Hex("abc") == "06B05AB6733A618578AF5F94892F3950"

var x = initXxh3_64()               # streaming (also initXxh32/initXxh64/initXxh3_128)
x.update(toBytes("hello "))
x.update(toBytes("world"))
assert x.finish() == xxh3_64bits(toBytes("hello world"))
```

### X25519 key exchange

```nim
import nimcypher/encrypt
import nimcypher/utils

let (aliceSk, alicePk) = x25519KeyPair(randomBytes[32]())
let (bobSk, bobPk)     = x25519KeyPair(randomBytes[32]())
let shared = sharedSecret(aliceSk, bobPk)
assert shared == sharedSecret(bobSk, alicePk)
```

### EdDSA signatures

```nim
import nimcypher/sign
import nimcypher/utils

let kp  = generateSigningKeyPair(randomBytes[32]())
let sig = sign(kp.secretKey, toBytes("message"))
assert verify(kp.publicKey, toBytes("message"), sig)
```

### ECDSA signatures and ECDH (P-256/P-384/P-521, secp256k1)

Deterministic RFC 6979 signatures in JWS `R || S` format; ECDH yields the
x-coordinate as `coordLen` bytes:

```nim
import nimcypher/ecdsa
import nimcypher/utils

var (alicePriv, alicePub) = generateEcKeyPair(P256)
var (bobPriv, bobPub) = generateEcKeyPair(P256)
assert ecValidatePublicKey(alicePub) and ecValidatePublicKey(bobPub)

let sig = ecdsaSign(alicePriv, toBytes("message"))   # deterministic
assert ecdsaVerify(alicePub, toBytes("message"), sig)
assert ecdhSharedSecret(alicePriv, bobPub) == ecdhSharedSecret(bobPriv, alicePub)

wipeEcKey(alicePriv)
wipeEcKey(bobPriv)
```

### RSA signatures and encryption (RS/PS/OAEP)

PKCS#1 v1.5 (RS256/384/512), PSS with salt = hash len (PS256/384/512),
OAEP-SHA-1/SHA-256 and legacy PKCS1-v1_5 encryption. Keys `>= 2048` bits
for production; smaller sizes exist for tests only and are slow to generate
in pure Nim:

```nim
import nimcypher/rsa
import nimcypher/utils

var priv = generateRsaKeyPair(2048)
let pub = rsaPublicKey(priv)
let msg = toBytes("hello JOSE")

let sig = rsaPkcs1v15Sign(priv, rhSha256, msg)   # RS256; also rsaPssSign
assert rsaPkcs1v15Verify(pub, rhSha256, msg, sig)

let ct = rsaOaepEncrypt(pub, rhSha256, msg)     # RSA-OAEP-256
assert rsaOaepDecrypt(priv, rhSha256, ct) == msg

wipeRsaKey(priv)
```

### RSA performance

Indicative figures from `tests/bench_rsa.nim` on an x86_64 laptop
(`-d:danger`; results vary a few percent run to run). The default build is pure
Nim; the `nimsimd` build switches the Montgomery engine to 64-bit limbs with
MULX (needs BMI2, see
[Optional SIMD acceleration](#optional-simd-acceleration)):

| operation | pure Nim | with `nimsimd` |
| --- | ---: | ---: |
| RSA-1024 sign | ~1.5ms | ~1.3ms |
| RSA-1024 verify (e = 65537) | ~0.2ms | ~0.2ms |
| RSA-2048 sign | ~6.3ms | ~4.9ms |
| RSA-2048 verify (e = 65537) | ~0.7ms | ~0.7ms |
| RSA-1024 keygen | ~30ms | ~30ms |
| RSA-2048 keygen | ~1s | ~1s |

For reference, RSA-2048 signing took about 333ms with the generic big-integer
power before the internal Montgomery sliding-window engine landed (roughly 50x
faster in pure Nim, roughly 65x with the MULX tier). One RSA-2048 sign splits
into about 3.9ms for the two CRT exponentiations plus 1.4ms for blinding
(2.5ms plus 1.3ms with `nimsimd`).

### Utilities

```nim
import nimcypher/utils

let key  = randomBytes[32]()
let salt = generateSalt(16)
assert toHex(key).len == 64
assert constantTimeEqual(toBytes("abc"), toBytes("abc"))
var secret = @[byte 1, 2, 3]
wipe(secret)
assert secret == @[byte 0, 0, 0]
```

### Low-level API

For full control over every primitive (different Argon2 variants, Ed25519, Elligator,
raw ChaCha20, Poly1305, RSA/ECDSA parameters, the EdDSA building blocks, or the
streaming ChaCha20 extension), import the low-level modules:

```nim
import nimcypher/algos/x25519
import nimcypher/algos/ed25519
import nimcypher/algos/elligator
import nimcypher/algos/chacha20
import nimcypher/algos/rsa
import nimcypher/algos/ecdsa

let pk = x25519PublicKey(sk)
let (sk25519, pk25519) = ed25519KeyPair(seed)
let curve = elligatorMap(hidden)

var chachaCtx: Chacha20Context   # streaming ChaCha20 (NimCypher extension)
initChacha20X(chachaCtx, key, nonce24)
var cipher = chacha20Encrypt(chachaCtx, toBytes("stream me"))
cipher.add chacha20Final(chachaCtx)
```

See the test suite (`tests/`) for a complete walk-through of both layers.


## Benchmarks

`nimble bench` compares the pure-Nim port against the **C Monocypher library**
(installed system-wide and called through the FFI test bindings) and
[`nimcrypto`](https://github.com/cheatfate/nimcrypto) (`nimcrypto >= 0.7.3`,
installed via `nimble`).

All sides are compiled with `-d:danger --opt:speed`
(the port with `--mm:arc`; accelerated columns add their feature flag, see below).
The Monocypher ratios are `Monocypher time / NimCypher time`: **below 1 means
Monocypher is faster, above 1 means NimCypher is faster**. The `NimCypher+SIMD`
column shows the legacy nimsimd kernels (AES-NI, PCLMULQDQ, AVX2),
`NimCypher+JIT` the dynasm JIT backend; `-` means the primitive has no
accelerated kernel.

The `nimcrypto` column shows the same workloads through `nimcrypto` (HW-accelerated
where available via SHA-NI/AVX/AES-NI); `Nc/*` are `nimcrypto / NimCypher`,
`nimcrypto / SIMD`, `nimcrypto / JIT`.

Results vary a few percent run to run (x86_64 laptop, 2026-11-06,
Nim 2.4.0, `-d:danger --opt:speed --mm:arc`):

```
operation                    iters  Monocypher  NimCypher    +SIMD     +JIT  nimcrypto  M/Nim  M/SIMD  M/JIT  Nc/Nim  Nc/SIMD  Nc/JIT
blake2b 64B                 100000     0.0154s    0.0170s        -        -    0.0398s  0.91x       -      -   2.34x        -       -
blake2b 1024B                20000     0.0191s    0.0230s        -        -    0.0572s  0.83x       -      -   2.49x        -       -
blake2b 65536B                2000     0.1169s    0.1413s        -        -    0.3660s  0.83x       -      -   2.59x        -       -
blake2b 4x 1024B              5000     0.0208s    0.0250s  0.0160s  0.0194s          -  0.83x   1.30x  1.07x       -        -       -
blake2b 4x 65536B              200     0.0520s    0.0624s  0.0326s  0.0513s          -  0.83x   1.60x  1.01x       -        -       -
sha512 64B                   50000     0.0153s    0.0135s        -        -    0.0116s  1.13x       -      -   0.86x        -       -
sha512 1024B                 20000     0.0500s    0.0488s        -        -    0.0369s  1.02x       -      -   0.76x        -       -
sha512 65536B                 1000     0.1414s    0.1383s        -        -    0.0996s  1.02x       -      -   0.72x        -       -
chacha20 64B                 50000     0.0058s    0.0071s  0.0064s  0.0084s          -  0.82x   0.91x  0.69x       -        -       -
chacha20 1024B               20000     0.0303s    0.0377s  0.0284s  0.0315s          -  0.80x   1.07x  0.96x       -        -       -
chacha20 65536B               1000     0.0949s    0.1182s  0.0907s  0.0979s          -  0.80x   1.05x  0.97x       -        -       -
poly1305 1024B               50000     0.0258s    0.0264s        -        -          -  0.98x       -      -       -        -       -
poly1305 65536B               2000     0.0630s    0.0640s        -        -          -  0.98x       -      -       -        -       -
aead lock+unlock 1024B       10000     0.0450s    0.0530s  0.0447s  0.0475s          -  0.85x   1.01x  0.95x       -        -       -
aead lock+unlock 65536B        500     0.1272s    0.1508s  0.1243s  0.1301s          -  0.84x   1.02x  0.98x       -        -       -
x25519                        2000     0.1551s    0.1518s        -        -          -  1.02x       -      -       -        -       -
eddsa sign 1KB                1000     0.0405s    0.0397s        -        -          -  1.02x       -      -       -        -       -
eddsa check 1KB               1000     0.1150s    0.1136s        -        -          -  1.01x       -      -       -        -       -
ed25519 sign 1KB              1000     0.0444s    0.0422s        -        -          -  1.05x       -      -       -        -       -
ed25519 check 1KB             1000     0.1174s    0.1153s        -        -          -  1.02x       -      -       -        -       -
elligator map                 3000     0.0222s    0.0198s        -        -          -  1.12x       -      -       -        -       -
elligator rev                 3000     0.0213s    0.0190s        -        -          -  1.13x       -      -       -        -       -
argon2i 8blk 1pass              20     0.0003s    0.0004s        -        -          -  0.75x       -      -       -        -       -
aes-ctr 1024B                20000           -    0.1548s  0.0145s  0.0122s    0.4872s      -       -      -   3.15x   33.60x  39.93x
aes-ctr 65536B                1000           -    0.4957s  0.0451s  0.0379s    1.5236s      -       -      -   3.07x   33.78x  40.20x
aes-gcm lock+unlock 1024B     5000           -    0.0493s  0.0269s  0.0219s    0.2788s      -       -      -   5.66x   10.36x  12.73x
aes-gcm lock+unlock 65536B     300           -    0.1268s  0.0446s  0.0194s    1.0193s      -       -      -   8.04x   22.85x  52.54x
```

`+SIMD` is the legacy nimsimd build (`-d:features.nimcypher.nimsimd`),
`+JIT` the dynasm backend (`-d:features.nimcypher.nimdynasm`); the
`blake2b 4x` rows need the nimsimd flag to compile in, so their `+JIT`
values come from a combined-flags build where dispatch prefers JIT.
Scalar/Monocypher/nimcrypto columns are from the JIT run. On Nim 2.4
the harness needs `-d:nimNoLentIterators` to compile.

TLS bulk throughput (`tests/bench_tls.nim`, 16 KiB records, same machine):

```
suite                        nimcypher seal  nimcypher open  OpenSSL seal  OpenSSL open
AES-128-GCM (scalar)             112.9 MB/s      112.0 MB/s   2937.4 MB/s   3538.8 MB/s
AES-128-GCM (+JIT)              2638.9 MB/s     2654.9 MB/s   3000.6 MB/s   3581.5 MB/s
AES-256-GCM (scalar)              94.2 MB/s       93.6 MB/s   2840.3 MB/s   3362.7 MB/s
AES-256-GCM (+JIT)              2353.2 MB/s     2342.5 MB/s   2827.4 MB/s   3363.1 MB/s
ChaCha20-Poly1305 (scalar)       481.3 MB/s      481.5 MB/s   1951.9 MB/s   2157.9 MB/s
ChaCha20-Poly1305 (+JIT)         968.9 MB/s      982.5 MB/s   1962.6 MB/s   2193.8 MB/s
```

Both columns are whole one-shot operations (fresh context per record). The TLS
record layer reuses a cached `GcmSession` instead, which removes the per-record
key schedule: measured separately at 2879/2881 MB/s for AES-128-GCM 16 KiB
records, i.e. ~1.03x of OpenSSL's seal. Output is byte-identical to OpenSSL in
both directions — `tests/topenssl_aead.nim` drives libcrypto's EVP directly and
exchanges ciphertext and tags for AES-128/256-GCM and ChaCha20-Poly1305 across
every kernel size class (0 B to 16 KiB + 1), with and without AAD, plus tamper
rejection and the session path.

The port matches or slightly beats C for SHA-512, X25519, EdDSA/Ed25519 and Elligator.
On the symmetric primitives the scalar port is roughly 0.75-0.90x vs C Monocypher; with
the JIT backend, ChaCha20 reaches parity, AES-CTR gets a ~13x boost from AES-NI,
and AES-GCM reaches ~9.6x over the scalar path at 1 KiB and ~25x at 64 KiB
(one-shot `gcmLock`; 971 vs 102 MB/s and 2864 vs 115 MB/s).
Compared to `nimcrypto` (same machine,
same compiler flags), NimCypher is **2.3-2.6x faster on BLAKE2b**, **~0.7x on SHA-512**
(`nimcrypto` benefits from SHA-NI), and **~3.1x (scalar) / ~40x (JIT) faster on AES-CTR**
and **~8x / ~53x on AES-GCM**.

The AES scalars are constant-time bitsliced implementations verified against the NIST test vectors;
with AES-NI enabled, AES-GCM performance matches or beats the C Monocypher AES-NI path.

The `blake2b 4x` rows hash four messages at once with `blake2bParallel` (the C and
scalar-Nim columns run four one-shot hashes for the same work); the SIMD kernel brings
batched BLAKE2b to ~1.3-1.4x C.


## Testing

```
nimble test
```

Runs three suites:

- **Vector tests**: Monocypher's own deterministic test vectors (RFC and known-answer
  vectors, over 16,000 of them), ported into `tests/vectors.nim`, covering every primitive.
- **Interop tests**: byte-for-byte cross-checks between the pure-Nim port and the real C
  Monocypher library: key exchange, signatures, AEAD encryption/decryption, streaming,
  hashing, Argon2, Elligator, and constant-time verification.
- **OpenSSL interop tests** (`topenssl.nim`): live two-way cross-checks against the system
   `openssl` CLI over freshly generated keys: RSA PKCS#1 v1.5 / PSS / OAEP, ECDSA
   (P-256, P-384, secp256k1), AES-ECB/CBC/CTR, full SHA-2 + SHA-1 digests, MD5 digests,
   HMAC-SHA-224/256/512-224/512-256, HMAC-MD5, IETF ChaCha20,
  X25519, and Ed25519. AES-GCM is covered by NIST vectors in `tgcm` instead (`openssl
  enc` rejects AEAD ciphers).
- **High-level tests**: round trips and error handling for the `import nimcypher` API
  (`thighlevel.nim`), cross-checked against the low-level primitives.

The interop tests require a system-installed C Monocypher discoverable via `pkg-config`
(headers in the include path, `libmonocypher.a` linkable). They use FFI bindings copied
from the `openpeeps/e2ee` package (see `tests/monocypher_ffi.nim`).

The OpenSSL suite shells out to the `openssl` binary at test time. If none is found it
passes trivially with a skip note; set `NIMCYPHER_REQUIRE_OPENSSL=1` (as CI does) to
fail loudly instead. On macOS, point PATH at the Homebrew OpenSSL 3 first: the system
LibreSSL lacks some `pkeyutl` options the suite needs.


## Benchmarking

```
nimble bench
```

`nimble bench` installs nimsimd, builds the suite with `-d:features.nimcypher.nimsimd`
and prints a single table with the scalar reference (`NimCypher`) and the
SIMD-accelerated (`NimCypher+SIMD`) columns side by side (see
[Benchmarks](#benchmarks)). The scalar-only baseline is obtained by compiling
`tests/bench.nim` directly without the feature flag. The dynasm JIT backend
(`-d:features.nimcypher.nimdynasm`, off by default) adds the `NimCypher+JIT`
column; on Nim 2.4 the harness needs `-d:nimNoLentIterators` to compile.


## Optional SIMD acceleration

NimCypher ships optional SIMD-accelerated kernels behind the `nimsimd` feature flag.
They are **off by default** (the library stays zero-dependency and runs on any CPU)
and are selected with the Nimble `nimsimd` feature:

```
nimble install nimsimd                       # install the dependency
nim c -d:features.nimcypher.nimsimd app.nim  # enable at build time
```

Consumers enable it from their own `*.nimble` file instead:

```
requires "nimcypher >= 0.1.0[nimsimd]"
```

Requirements and what gets accelerated:

- **amd64**: AES-NI (`-maes`) and PCLMULQDQ (`-mpclmul`) for AES block cipher and
  GHASH, AVX2 (`-mavx2`) for ChaCha20 and batched BLAKE2b.
- **arm64**: ARMv8 Crypto Extensions (`+crypto`) for AES block cipher, NEON for ChaCha20
  and batched BLAKE2b. GHASH uses the scalar CT reference path on ARM (PMULL integration
  planned).
- Accelerates **AES-128/192/256** (8 blocks in parallel on amd64 via AES-NI, 4 blocks on
  arm64 via ARMv8 AESE/AESMC) and therefore all **AES-GCM** encryption/decryption
  (AES-NI + PCLMULQDQ on amd64). Also accelerates **ChaCha20** (`chacha20Djb/Ietf/X`,
  HChaCha20) and the ChaCha20 half of **AEAD**. It also accelerates **batched BLAKE2b**
  through `blake2bParallel`, which hashes four messages at once with one SIMD lane each.
- Accelerates **RSA** on amd64 via 64-bit-limb Montgomery arithmetic with MULX
  (BMI2, `-mbmi2`): the `nimsimd` binary requires BMI2 (Intel Haswell / AMD
  Excavator and newer). RSA-2048 sign drops from ~6.3ms to ~4.9ms
  (`tests/bench_rsa.nim`); other architectures keep the portable 32-bit path.

On x86_64 the two-block AVX2 kernel for ChaCha20 roughly reaches parity with C Monocypher
on the full one-shot, while AES-NI gives a ~13x improvement over the bitsliced scalar
core on bulk operations (CTR/ECB). The GCM construction benefits from both AES-NI and
PCLMULQDQ, reaching ~6.5x over the scalar implementation at 64 KiB
(~23x on 16 KiB TLS records: 2639 vs 113 MB/s, ~1.14x off OpenSSL's seal).

The scalar constant-time bitsliced AES core always stays available as the reference path
and is cross-checked byte-for-byte by the test suite (`nimble test_simd` runs ChaCha20,
AEAD, BLAKE2b, AES, GCM, Montgomery/RSA and interop tests with the feature enabled).
The portable 32-bit Montgomery path likewise stays the RSA default; the MULX tier is
differential-tested against it (`tests/tmontgomery.nim`, all bit sizes to 4096).


## Verification & provenance

NimCypher is a faithful port of **Monocypher 4.0.3** (`monocypher.c` and the optional
`monocypher-ed25519.c`). It is verified in two independent ways:

1. It passes Monocypher's own deterministic test-vector suite, ported into Nim.
2. It produces byte-identical output to the C Monocypher library across all primitives
   (key exchange, signatures, AEAD, hashing, Argon2, Elligator), including cross
   signing/verifying between the two implementations.

Constant-time properties are preserved: the field arithmetic uses the same carry chains
and bit tricks as the reference C code, secret-dependent comparisons go through
`constantTimeEqual`, and `wipe` uses a compiler barrier so it is never optimized away.


## Security notes

- The low-level primitives have **no random number generator**: provide keys, nonces and
  seeds yourself. The high-level API's `randomBytes` / `generateSalt` use `urandom`.
- Never reuse a ChaCha20 nonce with the same key. The XChaCha20 AEAD nonce is 192 bits,
  so random nonces (`seal`) are safe in practice.
- For AES-GCM, use a unique 96-bit nonce per message under a given key. `gcmSeal`
  generates a random nonce; never reuse nonce+key.
- `decrypt` / `unseal` / `aeadStreamRead` / `aesGcmDecrypt` verify the MAC in constant
  time and never return plaintext on failure; they raise `ValueError` instead.
- The AES scalar core is constant-time (bitsliced, no lookup tables); AES-NI and
  PCLMULQDQ are hardware constant-time by design. The HW path is only activated behind
  the `nimsimd` feature flag.
- RSA private operations use CRT + RSA blinding to mitigate the variable-time
  `powmod` (`pkg/bigints`); OAEP/PKCS1-v1_5 decoders use a single `decryption error`
  message. Prefer OAEP over PKCS1-v1_5 for new uses. Use keys `>= 2048` bits.
- ECDSA scalar multiplication is a variable-time double-and-add (affine/Jacobian
  coordinates with `invmod`); signatures use deterministic RFC 6979 nonces (no
  RNG failure mode), but do not rely on timing side-channel resistance for
  ECDSA/RSA private ops in hostile shared-CPU environments.
- RSA private ops run on an internal Montgomery sliding-window exponentiation
  (pure Nim, `algos/internal/montgomery`, blinding inverse via binary GCD):
   ~6.3ms/sign and ~1s 2048-bit keygen on a laptop (`tests/bench_rsa.nim`),
   ~50x faster than the generic `pkg/bigints` `powmod`; the `nimsimd` build
   switches to 64-bit MULX limbs (`internal/montgomery64`, ~4.9ms/sign, needs
  BMI2). `wipeRsaKey` / `wipeEcKey` drop BigInt references (GC frees the
  limbs); ephemeral `seq[byte]` buffers are scrubbed via `wipe`.
- Use `constantTimeEqual`, not `==`, to compare secrets.
- Wipe secrets with `wipe` once you are done with them.
- `MD5` is broken (practical collisions) and `HMAC-MD5` is legacy only:
  both exist for interop with old formats, never for new designs.
- `xxHash` (`XXH32`/`XXH64`/`XXH3`) is not cryptographic: checksums and
  hash tables only, never signatures, MACs, or password hashing.


> [NOTE]
> JOSE (JWS/JWE/JWK) lives in a separate package:
> [nimbase/jose](https://github.com/nimbase/jose), pure-Nim JOSE based
> on nimcypher.


## Roadmap

Direction, not a commitment. Items land as pure-Nim, tested against
reference vectors and OpenSSL interop before they are documented here.

**Next (asymmetric usability):**
- RSA/EC key export and JWK import/export (`n`, `e`, `d`, `x`, `y`,
  `crv`) for the supported RSA and EC curves. PKCS#1 / PKCS#8 / SEC1
  DER + PEM private-key import already exists in `tls/keys`.

**Later (further algos):**
- SHA-3 / Keccak and HMAC-SHA3 (FIPS 202) alongside the SHA-2 family.
- AES Key Wrap (KW/KWP, NIST SP 800-38F) for JOSE key management.
- PBKDF2-HMAC-SHA-2 for legacy password-based key derivation
  (Argon2id stays the default).
- Minimal HPKE (DHKEM + AEAD) built from the existing ECDH/HKDF/AEAD
  pieces. TLS 1.3 `HKDF-Expand-Label` already exists in
  `tls/key_schedule`.

**Hardening (no new algos):**
- Constant-time EC field arithmetic to replace the current variable-time
  double-and-add (ECDSA) and blinded `powmod` (RSA) paths.
- SHA-256/SHA-512 hardware kernels (SHA-NI) behind the existing
  `nimsimd` feature flag, mirroring the AES-NI/ChaCha20-AVX2 approach.
- Expanded `nimble bench` rows for SHA-256/384, RSA and ECDSA vs
  OpenSSL/nimcrypto.

Out of scope: CRL/OCSP, name constraints, policies, IDNA; encrypted
PKCS#8, multi-prime RSA, and explicit-curve parameters (see
`tls/verify` and `tls/keys`).


### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/nimcypher/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/nimcypher/fork)


### 🎩 License
`BSD-2-Clause` OR `CC0-1.0` license. NimCypher is a port of [Monocypher](https://monocypher.org/) in Nim.

[Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright &copy; 2026 OpenPeeps & Contributors &mdash; All rights reserved.
