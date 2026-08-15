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

NimCypher is a **pure-Nim port of [Monocypher](https://monocypher.org/) 4.0.3**: a small,
auditable, easy-to-use cryptographic library. It has **zero C dependency** and no runtime
dependencies beyond the Nim standard library, so it is easy to deploy and easy to audit.

It ships two layers:

- **A high-level, easy-to-remember API** (`import nimcypher`) for the common tasks:
  hashing, authenticated encryption and sealing, X25519 key exchange, signatures and
  password hashing.
- **The low-level primitives** (`nimcypher/algos/...`) for fine-grained control, exposing
  the full Monocypher surface with an idiomatic Nim style: `openArray[byte]` in,
  `seq[byte]` / `array[N, byte]` out, contexts as objects with `init` / `update` / `final`,
  and `Option` / `bool` where an operation can fail.

Every primitive is cross-checked byte-for-byte against the reference C implementation by
the test suite.

> [!NOTE]
> NimCypher is a **port** of [Monocypher](https://github.com/LoupVaillant/monocypher) in pure Nim. It does **not** aim to exceed
> Monocypher or Libsodium in security or stability. The port is a best-effort reimplementation
> verified against the C reference and its test vectors, but it has not been independently audited.
>
> For production cryptography, you may prefer the battle-tested C library (Monocypher, Libsodium) or a reviewed
> native binding to it. **Use NimCypher at your own risk.** 🤯


## Key features

High-level API (`import nimcypher`):
- **Authenticated encryption & sealing**: `encrypt` / `decrypt`, `seal` / `unseal`
  (XChaCha20-Poly1305, RFC 8439), streaming via `aeadStreamInitX/Djb/Ietf`
- **Hashing**: `blake` / `blakeKeyed`, `sha512`, `sha512Hmac`, `hkdfSha512`
- **Password hashing**: `hashPassword` / `verifyPassword` / `deriveKeyFromPassword` (Argon2id)
- **Key exchange**: `x25519KeyPair` / `sharedSecret` / `computeChallengeMac`
- **Signatures**: `generateSigningKeyPair` / `sign` / `verify` (EdDSA with BLAKE2b)
- **Utilities**: `constantTimeEqual`, `wipe`, `randomBytes`, `toHex` / `fromHex`

Low-level primitives (`nimcypher/algos/...`):
- **Authenticated encryption**: `aeadLock` / `aeadUnlock` + streaming `AeadContext`
- **Hashing**: BLAKE2b (keyed & unkeyed), SHA-512, HMAC, HKDF
- **Password hashing**: Argon2 (`d`, `i`, `id`)
- **Key exchange**: X25519 (incl. dirty keys, scalar inverse / OPRF, EdDSA↔X25519 conversion)
- **Signatures**: EdDSA (BLAKE2b + Curve25519), Ed25519, Ed25519ph (SHA-512)
- **Steganography & PAKE**: Elligator 2 (map / reverse map / key pair)
- **Stream ciphers**: ChaCha20 (DJB, IETF, XChaCha20, HChaCha20), Poly1305
- **EdDSA building blocks**: `trimScalar`, `reduce`, `mulAdd`, `scalarbase`, `checkEquation`


## Examples

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

### Hashing: BLAKE2b, SHA-512, HMAC, HKDF

```nim
import nimcypher/hash
import nimcypher/utils

let digest = blake(toBytes("hello world"))              # 32-byte BLAKE2b digest
let mac    = blakeKeyed(toBytes("msg"), toBytes("key")) # keyed (MAC)
let sha    = sha512Hex("hello world")                   # hex string
let hmac   = sha512Hmac(toBytes("key"), toBytes("msg"))
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
(installed system-wide and called through the FFI test bindings). Both sides are
compiled with `-d:danger --opt:speed` (the port with `--mm:arc` and
`-d:features.nimcypher.nimsimd`). The ratio is
`Monocypher time / NimCypher time`: **below 1 means Monocypher is faster, above 1 means
NimCypher is faster**. The `NimCypher+SIMD` column shows the SIMD-accelerated kernels;
`-` means the primitive has no SIMD kernel (BLAKE2b, SHA-512, Poly1305, X25519,
signatures, Elligator, Argon2). Results vary a few percent run to run.

| operation | iters | Monocypher | NimCypher | NimCypher+SIMD | M/Nim | M/SIMD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| blake2b 64B | 100000 | 0.0151s | 0.0178s | - | 0.85x | - |
| blake2b 1024B | 20000 | 0.0192s | 0.0255s | - | 0.75x | - |
| blake2b 65536B | 2000 | 0.1169s | 0.1568s | - | 0.75x | - |
| blake2b 4x 1024B | 5000 | 0.0207s | 0.0271s | 0.0164s | 0.76x | 1.26x |
| blake2b 4x 65536B | 200 | 0.0467s | 0.0621s | 0.0326s | 0.75x | 1.43x |
| sha512 64B | 50000 | 0.0156s | 0.0151s | - | 1.03x | - |
| sha512 1024B | 20000 | 0.0502s | 0.0533s | - | 0.94x | - |
| sha512 65536B | 1000 | 0.1411s | 0.1509s | - | 0.93x | - |
| chacha20 64B | 50000 | 0.0058s | 0.0070s | 0.0075s | 0.83x | 0.77x |
| chacha20 1024B | 20000 | 0.0301s | 0.0377s | 0.0295s | 0.80x | 1.02x |
| chacha20 65536B | 1000 | 0.0963s | 0.1193s | 0.0927s | 0.81x | 1.04x |
| poly1305 1024B | 50000 | 0.0244s | 0.0281s | - | 0.87x | - |
| poly1305 65536B | 2000 | 0.0603s | 0.0706s | - | 0.85x | - |
| aead lock+unlock 1024B | 10000 | 0.0447s | 0.0543s | 0.0458s | 0.82x | 0.98x |
| aead lock+unlock 65536B | 500 | 0.1271s | 0.1532s | 0.1289s | 0.83x | 0.99x |
| x25519 | 2000 | 0.1560s | 0.1549s | - | 1.01x | - |
| eddsa sign 1KB | 1000 | 0.0402s | 0.0393s | - | 1.02x | - |
| eddsa check 1KB | 1000 | 0.1179s | 0.1158s | - | 1.02x | - |
| ed25519 sign 1KB | 1000 | 0.0431s | 0.0419s | - | 1.03x | - |
| ed25519 check 1KB | 1000 | 0.1182s | 0.1168s | - | 1.01x | - |
| elligator map | 3000 | 0.0219s | 0.0199s | - | 1.10x | - |
| elligator rev | 3000 | 0.0212s | 0.0192s | - | 1.10x | - |
| argon2i 8blk 1pass | 20 | 0.0003s | 0.0005s | - | 0.62x | - |

The port matches or slightly beats C for SHA-512, X25519, EdDSA/Ed25519 and Elligator.
On the symmetric primitives the scalar port is roughly 1.2–1.3x slower than C; with the
SIMD kernels, ChaCha20 and the ChaCha20 half of AEAD reach **parity with (and at 1 KB+
slightly beat) C Monocypher**. The `blake2b 4x` rows hash four messages at once with
`blake2bParallel` (the C and scalar-Nim columns run four one-shot hashes for the same
work); the SIMD kernel brings batched BLAKE2b to **~1.3–1.4x C**.


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

NimCypher ships optional SIMD-accelerated ChaCha20 kernels behind a feature flag. They
are **off by default** — the library stays zero-dependency and runs on any CPU — and are
selected with the Nimble `nimsimd` feature:

```
nimble install nimsimd                       # install the dependency
nim c -d:features.nimcypher.nimsimd app.nim  # enable at build time
```

Consumers enable it from their own `*.nimble` file instead:

```
requires "nimcypher >= 0.1.0[nimsimd]"
```

Requirements and what gets accelerated:

- **amd64**: an AVX2-capable CPU (the whole SIMD build is compiled with `-mavx2`); uses a
  two-block AVX2 kernel.
- **arm64**: NEON (baseline on all ARMv8 CPUs); uses a four-lane NEON kernel.
- Accelerates **ChaCha20** (`chacha20Djb/Ietf/X`, HChaCha20) and therefore the ChaCha20
  half of **AEAD** (`aeadLock`/`aeadUnlock`, streaming). It also accelerates **batched
  BLAKE2b** through `blake2bParallel` (`nimcypher/algos/blake2b`), which hashes four
  messages at once with one SIMD lane each — equivalent to four `blake2b` calls. The
  single-message BLAKE2b, SHA-512, Poly1305, Argon2 and the Curve25519/EdDSA math remain
  scalar.

On x86_64 with Clang the scalar ChaCha20 kernel is already auto-vectorized, so the
two-block AVX2 kernel is what actually moves the needle (roughly 1.3x on the full
one-shot, bringing ChaCha20 to parity with — and slightly past — C Monocypher). The SIMD
kernels are cross-checked byte-for-byte against the scalar reference and the C library by
the test suite (`nimble test_simd` runs ChaCha20, AEAD and interop tests with the feature
enabled).


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
- `decrypt` / `unseal` / `aeadStreamRead` verify the MAC in constant time and never return
  plaintext on failure — they raise `ValueError` instead.
- Use `constantTimeEqual`, not `==`, to compare secrets.
- Wipe secrets with `wipe` once you are done with them.


### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/nimcypher/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/nimcypher/fork)


### 🎩 License
`BSD-2-Clause` OR `CC0-1.0` license. NimCypher is a port of [Monocypher](https://monocypher.org/) in Nim.

[Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright &copy; 2026 OpenPeeps & Contributors &mdash; All rights reserved.
