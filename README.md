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
of AES-128/192/256 block cipher and AES-GCM authenticated encryption. It has **zero
C dependency** and no runtime dependencies beyond the Nim standard library, so it is
easy to deploy and easy to audit.

It ships two layers:

- **A high-level, easy-to-remember API** (`import nimcypher`) for the common tasks:
  AES-GCM sealing, hashing, authenticated encryption and sealing, X25519 key exchange,
  signatures and password hashing.
- **The low-level primitives** (`nimcypher/algos/...`) for fine-grained control, exposing
  the full surface with an idiomatic Nim style: `openArray[byte]` in,
  `seq[byte]` / `array[N, byte]` out, contexts as objects with `init` / `update` / `final`,
  and `Option` / `bool` where an operation can fail.

Every primitive is cross-checked byte-for-byte against the reference C Monocypher
implementation and the NIST test-vector suite.


## Key features

High-level API (`import nimcypher`):
- **AES-GCM sealing**: `gcmSeal` / `gcmOpen` (AES-256-GCM with random 96-bit nonces)
- **AES encryption**: `aesEcbEncrypt` / `aesCbcEncrypt` / `aesCtrCrypt` / `aesOfbCrypt` / `aesCfbEncrypt`
- **Authenticated encryption & sealing**: `encrypt` / `decrypt`, `seal` / `unseal`
  (XChaCha20-Poly1305, RFC 8439), streaming via `aeadStreamInitX/Djb/Ietf`
- **Hashing**: `blake` / `blakeKeyed`, `sha512`, `sha512Hmac`, `sha1Hmac` (HMAC-SHA-1, RFC 2202), `hkdfSha512`
- **Password hashing**: `hashPassword` / `verifyPassword` / `deriveKeyFromPassword` (Argon2id)
- **Key exchange**: `x25519KeyPair` / `sharedSecret` / `computeChallengeMac`
- **Signatures**: `generateSigningKeyPair` / `sign` / `verify` (EdDSA with BLAKE2b)
- **Utilities**: `constantTimeEqual`, `wipe`, `randomBytes`, `toHex` / `fromHex`

Low-level primitives (`nimcypher/algos/...`):
- **AES block cipher**: AES-128/192/256, ECB / CBC / CTR / CFB128 / OFB, streaming contexts
- **AES-GCM**: authenticated encryption, streaming, NIST SP 800-38D
- **Authenticated encryption**: `aeadLock` / `aeadUnlock` + streaming `AeadContext`
- **Hashing**: BLAKE2b (keyed & unkeyed), SHA-512, HMAC, HMAC-SHA-1, HKDF
- **Password hashing**: Argon2 (`d`, `i`, `id`)
- **Key exchange**: X25519 (incl. dirty keys, scalar inverse / OPRF, EdDSA↔X25519 conversion)
- **Signatures**: EdDSA (BLAKE2b + Curve25519), Ed25519, Ed25519ph (SHA-512)
- **Steganography & PAKE**: Elligator 2 (map / reverse map / key pair)
- **Stream ciphers**: ChaCha20 (DJB, IETF, XChaCha20, HChaCha20), Poly1305
- **EdDSA building blocks**: `trimScalar`, `reduce`, `mulAdd`, `scalarbase`, `checkEquation`


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

### Hashing: BLAKE2b, SHA-512, HMAC, HMAC-SHA-1, HKDF

```nim
import nimcypher/hash
import nimcypher/utils

let digest = blake(toBytes("hello world"))              # 32-byte BLAKE2b digest
let mac    = blakeKeyed(toBytes("msg"), toBytes("key")) # keyed (MAC)
let sha    = sha512Hex("hello world")                   # hex string
let hmac   = sha512Hmac(toBytes("key"), toBytes("msg"))
let hmac1  = sha1Hmac(toBytes("key"), toBytes("msg"))   # 20-byte HMAC-SHA-1 (RFC 2202)
let okm    = hkdfSha512(toBytes("ikm"), @[], toBytes("info"), 32)
assert okm.len == 32
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

For full control over every primitive — different Argon2 variants, Ed25519, Elligator,
raw ChaCha20, Poly1305, the EdDSA building blocks, or the streaming ChaCha20 extension —
import the low-level modules:

```nim
import nimcypher/algos/x25519
import nimcypher/algos/ed25519
import nimcypher/algos/elligator
import nimcypher/algos/chacha20

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
(the port with `--mm:arc`, `-d:features.nimcypher.nimsimd`. The Monocypher ratios are
`Monocypher time / NimCypher time`: **below 1 means Monocypher is faster, above 1 means
NimCypher is faster**. The `NimCypher+SIMD` column shows the SIMD-accelerated kernels
(AES-NI, PCLMULQDQ, AVX2); `-` means the primitive has no SIMD kernel.

The `nimcrypto` column shows the same workloads through `nimcrypto` (HW-accelerated
where available via SHA-NI/AVX/AES-NI); `Nc/Nim` and `Nc/SIMD` are
`nimcrypto / NimCypher` and `nimcrypto / SIMD`. Results vary a few percent run to run.

| operation | iters | MCypher | NCypher | +SIMD | NCrypto | M/Nim | M/SIMD | Nc/Nim | Nc/SIMD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blake2b 64B | 100000 | 0.0155s | 0.0182s | - | 0.0412s | 0.85x | - | 2.26x | - |
| blake2b 1024B | 20000 | 0.0196s | 0.0256s | - | 0.0602s | 0.77x | - | 2.35x | - |
| blake2b 65536B | 2000 | 0.1192s | 0.1611s | - | 0.3664s | 0.74x | - | 2.27x | - |
| blake2b 4x 1024B | 5000 | 0.0207s | 0.0277s | 0.0169s | - | 0.75x | 1.23x | - | - |
| blake2b 4x 65536B | 200 | 0.0473s | 0.0620s | 0.0345s | - | 0.76x | 1.37x | - | - |
| sha512 64B | 50000 | 0.0167s | 0.0152s | - | 0.0126s | 1.10x | - | 0.83x | - |
| sha512 1024B | 20000 | 0.0500s | 0.0549s | - | 0.0378s | 0.91x | - | 0.69x | - |
| sha512 65536B | 1000 | 0.1444s | 0.1557s | - | 0.1065s | 0.93x | - | 0.68x | - |
| chacha20 64B | 50000 | 0.0060s | 0.0076s | 0.0077s | - | 0.79x | 0.77x | - | - |
| chacha20 1024B | 20000 | 0.0308s | 0.0394s | 0.0304s | - | 0.78x | 1.01x | - | - |
| chacha20 65536B | 1000 | 0.0961s | 0.1223s | 0.0958s | - | 0.79x | 1.00x | - | - |
| poly1305 1024B | 50000 | 0.0257s | 0.0296s | - | - | 0.87x | - | - | - |
| poly1305 65536B | 2000 | 0.0627s | 0.0703s | - | - | 0.89x | - | - | - |
| aead lock+unlock 1024B | 10000 | 0.0457s | 0.0556s | 0.0467s | - | 0.82x | 0.98x | - | - |
| aead lock+unlock 65536B | 500 | 0.1275s | 0.1571s | 0.1328s | - | 0.81x | 0.96x | - | - |
| x25519 | 2000 | 0.1580s | 0.1549s | - | - | 1.02x | - | - | - |
| eddsa sign 1KB | 1000 | 0.0417s | 0.0400s | - | - | 1.04x | - | - | - |
| eddsa check 1KB | 1000 | 0.1189s | 0.1179s | - | - | 1.01x | - | - | - |
| ed25519 sign 1KB | 1000 | 0.0439s | 0.0423s | - | - | 1.04x | - | - | - |
| ed25519 check 1KB | 1000 | 0.1213s | 0.1200s | - | - | 1.01x | - | - | - |
| elligator map | 3000 | 0.0227s | 0.0203s | - | - | 1.12x | - | - | - |
| elligator rev | 3000 | 0.0221s | 0.0202s | - | - | 1.09x | - | - | - |
| argon2i 8blk 1pass | 20 | 0.0003s | 0.0005s | - | - | 0.62x | - | - | - |
| aes-ctr 1024B | 20000 | - | 0.1500s | 0.0141s | 0.5010s | - | 10.61x | 3.34x | 35.44x |
| aes-ctr 65536B | 1000 | - | 0.4818s | 0.0443s | 1.5668s | - | 10.88x | 3.25x | 35.37x |
| aes-gcm lock+unlock 1024B | 5000 | - | 0.0876s | 0.0612s | 0.2855s | - | 1.43x | 3.26x | 4.67x |
| aes-gcm lock+unlock 65536B | 300 | - | 0.2868s | 0.1824s | 1.0398s | - | 1.57x | 3.62x | 5.70x |

The port matches or slightly beats C for SHA-512, X25519, EdDSA/Ed25519 and Elligator.
On the symmetric primitives the scalar port is roughly 0.75-0.90x vs C Monocypher; with
the SIMD kernels, ChaCha20 reaches parity, AES-CTR gets a ~10x boost from AES-NI,
and AES-GCM reaches ~1.5x over the scalar path. Compared to `nimcrypto` (same machine,
same compiler flags), NimCypher is **2.3x faster on BLAKE2b**, **~0.7x on SHA-512**
(`nimcrypto` benefits from SHA-NI), and **3.3x (scalar) / 35x (SIMD) faster on AES-CTR**
and **3.3x / 4.7x on AES-GCM**.

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
- **High-level tests**: round trips and error handling for the `import nimcypher` API
  (`thighlevel.nim`), cross-checked against the low-level primitives.

The interop tests require a system-installed C Monocypher discoverable via `pkg-config`
(headers in the include path, `libmonocypher.a` linkable). They use FFI bindings copied
from the `openpeeps/e2ee` package (see `tests/monocypher_ffi.nim`).


## Benchmarking

```
nimble bench
```

`nimble bench` installs nimsimd, builds the suite with `-d:features.nimcypher.nimsimd`
and prints a single Markdown table with both the scalar reference (`NimCypher`) and the
SIMD-accelerated (`NimCypher+SIMD`) columns side by side (see
[Benchmarks](#benchmarks)). The scalar-only baseline is obtained by compiling
`tests/tbench.nim` directly without the feature flag.


## Optional SIMD acceleration

NimCypher ships optional SIMD-accelerated kernels behind the `nimsimd` feature flag.
They are **off by default** — the library stays zero-dependency and runs on any CPU —
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

On x86_64 the two-block AVX2 kernel for ChaCha20 roughly reaches parity with C Monocypher
on the full one-shot, while AES-NI gives a ~10x improvement over the bitsliced scalar
core on bulk operations (CTR/ECB). The GCM construction benefits from both AES-NI and
PCLMULQDQ, reaching ~1.5x over the scalar implementation.

The scalar constant-time bitsliced AES core always stays available as the reference path
and is cross-checked byte-for-byte by the test suite (`nimble test_simd` runs ChaCha20,
AEAD, BLAKE2b, AES, GCM and interop tests with the feature enabled).


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
  time and never return plaintext on failure — they raise `ValueError` instead.
- The AES scalar core is constant-time (bitsliced, no lookup tables); AES-NI and
  PCLMULQDQ are hardware constant-time by design. The HW path is only activated behind
  the `nimsimd` feature flag.
- Use `constantTimeEqual`, not `==`, to compare secrets.
- Wipe secrets with `wipe` once you are done with them.


### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/nimcypher/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/nimcypher/fork)


### 🎩 License
`BSD-2-Clause` OR `CC0-1.0` license. NimCypher is a port of [Monocypher](https://monocypher.org/) in Nim.

[Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright &copy; 2026 OpenPeeps & Contributors &mdash; All rights reserved.
