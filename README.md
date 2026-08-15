<p align="center">
  NimCypher is a port of Monocypher in Nim
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
> NimCypher is a **port** of Monocypher in pure Nim. It does **not** aim to exceed
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
- **Hashing: BLAKE2b (keyed & unkeyed), SHA-512, HMAC, HKDF
- **Password hashing**: Argon2 (`d`, `i`, `id`)
- **Key exchange**: X25519 (incl. dirty keys, scalar inverse / OPRF, EdDSA↔X25519 conversion)
- **Signatures**: EdDSA (BLAKE2b + Curve25519), Ed25519, Ed25519ph (SHA-512)
- **Steganography & PAKE**: Elligator 2 (map / reverse map / key pair)
- **Stream ciphers**: ChaCha20 (DJB, IETF, XChaCha20, HChaCha20), Poly1305
- **EdDSA building blocks**: `trimScalar`, `reduce`, `mulAdd`, `scalarbase`, `checkEquation`


## Examples

The high-level API is intentionally simple. Keys and nonces are fixed-size byte arrays;
generate them with `randomBytes` (backed by `urandom`).

```nim
import nimcypher

# ---- Hashing ----
let digest = blake(toBytes("hello world"))         # 32-byte BLAKE2b digest
let mac    = blakeKeyed(toBytes("msg"), toBytes("key")) # keyed (MAC)
let sha    = sha512Hex("hello world")              # hex string
let hmac   = sha512Hmac(toBytes("key"), toBytes("msg"))
let okm    = hkdfSha512(toBytes("ikm"), @[], toBytes("info"), 32)

# ---- Authenticated encryption (XChaCha20-Poly1305) ----
let key   = randomBytes[32]()
let nonce = randomBytes[24]()   # random nonces are safe with XChaCha20
let (ciphertext, tag) = encrypt(toBytes("Attack at dawn"), key, nonce)
let plain = decrypt(ciphertext, tag, key, nonce)
doAssert plain == toBytes("Attack at dawn")

# ---- Sealing (random nonce per message) ----
let sealed = seal(toBytes("secret"), key)
let opened = unseal(sealed, key)
doAssert opened == toBytes("secret")

# ---- Streaming AEAD (encrypt a stream / large file) ----
var stream = aeadStreamInitX(key, nonce)      # also initDjb / initIetf
let (ct1, mac1) = aeadStreamWrite(stream, toBytes("part one"))
let (ct2, mac2) = aeadStreamWrite(stream, toBytes("part two"))

# ---- Key exchange (X25519) ----
let (aliceSk, alicePk) = x25519KeyPair(randomBytes[32]())
let (bobSk, bobPk)     = x25519KeyPair(randomBytes[32]())
let shared = sharedSecret(aliceSk, bobPk)
doAssert shared == sharedSecret(bobSk, alicePk)

# ---- Signatures ----
let kp = generateSigningKeyPair(randomBytes[32]())
let sig = sign(kp.secretKey, toBytes("message"))
doAssert verify(kp.publicKey, toBytes("message"), sig)

# ---- Password hashing (Argon2id) ----
let stored = hashPassword("hunter2")
doAssert verifyPassword("hunter2", stored)

# ---- Constant-time utilities ----
doAssert constantTimeEqual(@[byte 1, 2], @[byte 1, 2])
var secret = @[byte 1, 2, 3]
wipe(secret)
```

`decrypt`, `unseal` and `aeadStreamRead` raise `ValueError` when authentication fails, so
a failed MAC never yields plaintext.

### Low-level API

For full control over every primitive — different Argon2 variants, Ed25519, Elligator,
raw ChaCha20, Poly1305, or the EdDSA building blocks — import the low-level modules:

```nim
import nimcypher/algos/x25519
import nimcypher/algos/ed25519
import nimcypher/algos/elligator

let pk = x25519PublicKey(sk)
let (sk25519, pk25519) = ed25519KeyPair(seed)
let curve = elligatorMap(hidden)
```

See the test suite (`tests/`) for a complete walk-through of both layers.


## Benchmarks

`nimble bench` compares the pure-Nim port against the **C Monocypher library** (installed
system-wide and called through the FFI test bindings). Both sides are compiled with
`-d:danger --opt:speed` (the port with `--mm:arc`). The ratio is
`Monocypher time / NimCypher time`: **below 1 means Monocypher is faster, above 1 means
NimCypher is faster**. Results vary a few percent run to run.

| operation | iters | Monocypher | NimCypher | M/N |
| --- | ---: | ---: | ---: | ---: |
| blake2b 64B | 100000 | 0.0150s | 0.0179s | 0.84x |
| blake2b 1024B | 20000 | 0.0196s | 0.0253s | 0.78x |
| blake2b 65536B | 2000 | 0.1174s | 0.1552s | 0.76x |
| sha512 64B | 50000 | 0.0156s | 0.0151s | 1.04x |
| sha512 1024B | 20000 | 0.0516s | 0.0543s | 0.95x |
| sha512 65536B | 1000 | 0.1435s | 0.1546s | 0.93x |
| chacha20 64B | 50000 | 0.0058s | 0.0075s | 0.77x |
| chacha20 1024B | 20000 | 0.0301s | 0.0366s | 0.82x |
| chacha20 65536B | 1000 | 0.0956s | 0.1156s | 0.83x |
| poly1305 1024B | 50000 | 0.0256s | 0.0279s | 0.92x |
| poly1305 65536B | 2000 | 0.0634s | 0.0685s | 0.93x |
| aead lock+unlock 1024B | 10000 | 0.0457s | 0.0533s | 0.86x |
| aead lock+unlock 65536B | 500 | 0.1274s | 0.1505s | 0.85x |
| x25519 | 2000 | 0.1575s | 0.1570s | 1.00x |
| eddsa sign 1KB | 1000 | 0.0417s | 0.0403s | 1.03x |
| eddsa check 1KB | 1000 | 0.1172s | 0.1158s | 1.01x |
| ed25519 sign 1KB | 1000 | 0.0445s | 0.0433s | 1.03x |
| ed25519 check 1KB | 1000 | 0.1173s | 0.1174s | 1.00x |
| elligator map | 3000 | 0.0225s | 0.0207s | 1.09x |
| elligator rev | 3000 | 0.0216s | 0.0197s | 1.10x |
| argon2i 8blk 1pass | 20 | 0.0003s | 0.0005s | 0.67x |

The port matches or slightly beats C for SHA-512, X25519, EdDSA/Ed25519 and Elligator, and
is roughly 1.1–1.6x slower on the symmetric primitives (BLAKE2b, ChaCha20, Poly1305, AEAD)
and Argon2.


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

Runs the benchmark suite in `tests/tbench.nim` (see [Benchmarks](#benchmarks)).


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
