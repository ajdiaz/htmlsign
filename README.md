# 🔐 hs — sign & verify HTML blocks with post-quantum cryptography

`hs` signs **blocks** of an HTML (SGML/XML) document and lets anyone verify
them — even after the bytes have crossed the network. A TLS connection can
prove *who* you are talking to, but it can't prove the *content* they serve
is the content you intended. `hs` freezes the exact bytes of a block into a
self-contained, post-quantum signature attribute.

```html
<div class="text" data-hs-signature="ML-KEM-768+ML-DSA-65+BASE64:QWsd....">
  <p>Some text</p>
  <img src="image.jpg">
</div>
```

---

## 🧬 What is it?

- **Sign** any block matched by a CSS selector (`div.text`, `#price`,
  `article[data-id="42"]`, …).
- The signature is computed over the **entire block**, including the root
  element and all attributes **except** `data-hs-signature` itself.
- The signed payload embeds the **ML-KEM + ML-DSA public keys** next to the
  signature, so verification is fully self-contained — no key database needed.
- **Verify** finds every signed block, recomputes its canonical bytes, and
  checks the embedded ML-DSA signature.
- Keys are stored **passphrase-encrypted** (Argon2id + XChaCha20-Poly1305),
  never in plaintext on disk.

---

## 📜 Cryptographic stack

| Layer | Algorithm | Crate |
|---|---|---|
| Key Encapsulation (KEM) | ML-KEM (CRYSTALS-Kyber) FIPS 203 | `ml-kem` |
| Digital Signatures | ML-DSA (CRYSTALS-Dilithium) FIPS 204 | `ml-dsa` |
| Symmetric encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| Key derivation | Argon2id (passphrase → symmetric key) | `argon2` |
| Compression | Zstandard / GZIP / BZIP2 / LZMA / DEFLATE | `zstd` / `flate2` / `bzip2` / `lzma-rs` |
| Binary encoding | BASE64 / ASCII85 | `base64` / `ascii85` |
| Randomness | `OsRng` | `rand` |

Pure-Rust crates only. The `pqcrypto` umbrella crate was deliberately avoided
due to RUSTSEC-2026-0164 (unmaintained).

---

## 🔑 Key management

Generate a passphrase-protected key pair:

```bash
$ hs gen-key --public-key key.pub
Enter passphrase for new key:
Confirm passphrase:
Generated key pair:
  secret key:   ~/.local/share/hs/keys/default.hskey
  kem:          ML-KEM-768
  dsa:          ML-DSA-65
  fingerprint:  7f6a2c...c3d09b
```

The public key is exported in armored form:

```
-----BEGIN HS PUBLIC KEY-----
ML-KEM-768 ML-DSA-65
9Xx... (base64 body, wrapped at 64 columns)
-----END HS PUBLIC KEY-----
```

Inspect a key file:

```bash
$ hs view-key
Key file: ~/.local/share/hs/keys/default.hskey
  kem:          ML-KEM-768
  dsa:          ML-DSA-65
  fingerprint:  7f6a2c...c3d09b
```

---

## ✍️ Signing

```bash
$ hs sign index.html div.text
Signed 1 block(s) in index.html
  key fingerprint: 7f6a2c...c3d09b
  <div> signed 47 bytes
```

Options: `-k key.hskey`, `-o out.html`, `--no-passphrase`,
`--passphrase-file FILE`.

---

## ✔️ Verifying

```bash
$ hs verify index.html
[0] <div> OK
      fingerprint: 7f6a2c...c3d09b
OK: 1 of 1 blocks verified.
```

Tampered content fails loudly:

```bash
$ hs verify tampered.html
[0] <div> FAIL
      reason: signature verification failed
FAIL: 0 of 1 blocks verified.
```

Use `-k key.pub` to additionally **require** that every block was signed by
that exact public key — defeating re-signing of altered content with a
different key:

```bash
$ hs verify index.html -k key.pub
```

### 🌐 Remote verification via URL

`hs verify` accepts an `http://` or `https://` URL instead of a local file:

```bash
$ hs verify https://example.org
Fetching https://example.org ...
[0] <div> OK
      fingerprint: 7f6a2c...c3d09b
OK: 1 of 1 blocks verified.
```

When given a URL, `hs`:

1. Fetches the document over **HTTPS** and validates the server's TLS
   certificate, failing hard on an invalid cert unless
   `--ignore-tls-errors` is passed.
2. Resolves the signing public key automatically from the DNS TXT record
   `_hs_key.example.org` and requires every signed block to match that
   key's fingerprint.

Publish the armored public key from `hs gen-key --public-key key.pub` as a
TXT record at `_hs_key.<your-domain>`. The record may be split across DNS
character-strings — `hs` stitches them back together. This closes the gap
TLS leaves open: TLS authenticates the *endpoint*, the `_hs_key` record pins
the *content*.

---

## 📋 CLI reference

```
hs gen-key [-o PATH] [--kem ML-KEM-768] [--dsa ML-DSA-65]
           [--public-key PATH] [--no-passphrase] [--passphrase-file FILE]
           [--argon2-mem KIB] [--argon2-time N] [--argon2-par N]

hs sign FILE SELECTOR [-k KEY.hskey] [-o OUT.html]
           [--no-passphrase] [--passphrase-file FILE]

hs verify FILE|URL [-k KEY.pub] [--ignore-tls-errors]

hs view-key [-k KEY.hskey] [--no-passphrase] [--passphrase-file FILE]
```

Global flags: `-n, --dry-run` prints what would happen and exits without
doing anything.

---

## 🚀 Build & development

```bash
make build      # cargo build
make test       # cargo test
make clippy     # cargo clippy --all-targets -- -D warnings
make fmt        # cargo fmt
make doc        # cargo doc --no-deps
make audit      # cargo audit
```

Or directly:

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

---

## 🔧 Design notes

- **Signature attribute format**:
  `data-hs-signature="ML-KEM-768+ML-DSA-65+BASE64:<payload>"` where the
  payload is `kem_pk || dsa_pk || signature`.
- **Self-contained**: the embedded public keys let `verify` work out of the
  box; trust comes from comparing fingerprints or supplying `-k`.
- **Memory safety**: no `unsafe`, secret material is zeroized, and all
  key material on disk is passphrase-encrypted.

## 📁 Project layout

```
src/
  lib.rs        crate-level API documentation
  cli.rs        clap CLI definitions
  crypto/       ML-KEM, ML-DSA, symmetric primitives, key file format
  format.rs     signature attribute encoding/parsing
  html.rs       HTML parsing, signing, verification, report rendering
  keys.rs       key generation, storage, public key armor
  net.rs        HTTPS fetch + DNS `_hs_key` key resolution
  main.rs       binary entry point and command dispatch
```
