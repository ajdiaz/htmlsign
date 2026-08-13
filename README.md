# 🔐 hs — sign & verify HTML blocks with post-quantum cryptography

`hs` signs **blocks** of an HTML (SGML/XML) document and lets anyone verify
them — even after the bytes have crossed the network. A TLS connection can
prove *who* you are talking to, but it can't prove the *content* they serve
is the content you intended. `hs` freezes the exact bytes of a block into a
self-contained, post-quantum signature attribute.

```html
<div class="text" data-hs-signature="SHA3-256+ML-KEM-768+ML-DSA-65+BASE64:QWsd....">
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
- **Minification-proof**: text whitespace is normalized before signing, so
  a server can minify or reformat the block without breaking its signature
  (content, attribute, and structural changes still fail).
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

`-k` accepts **either** an armored public key file (`key.pub`) **or** the
`.hskey` secret key file itself — the tool detects the format and unlocks
the secret key (prompting for its passphrase) to use the embedded public
half:

```bash
$ hs verify index.html -k ~/.local/share/hs/keys/default.hskey
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

Publish the public key from `hs export --txt` as a TXT record at
`_hs_key.<your-domain>`. The record may be split across DNS
character-strings — `hs` stitches them back together. This closes the gap
TLS leaves open: TLS authenticates the *endpoint*, the `_hs_key` record pins
the *content*.

### 📤 Exporting a key for DNS

Export the public key of an existing key file (for the TXT record) without
regenerating anything. Without `--txt`, the armored form is printed for
out-of-band distribution:

```bash
$ hs export -k ~/.local/share/hs/keys/default.hskey
-----BEGIN HS PUBLIC KEY-----
ML-KEM-768 ML-DSA-65
...
-----END HS PUBLIC KEY-----
```

Write it to a file with `-o`, or print it pre-split into DNS TXT
character-strings (≤255 bytes each, one per line) with `--txt`. The `--txt`
form uses a compact base-85 encoding (no PEM markers) whose alphabet is
DNS-safe — it excludes `"`, `\`, `;`, `(`, `)`, and whitespace — so every
line can be pasted verbatim between the double quotes of a TXT
character-string. The whole record stays under DNS's practical 4096-byte
limit: the default ML-KEM-768 + ML-DSA-65 key fits in ~3946 bytes, while
base64 armor would need 4329:

```bash
$ hs export -k key.hskey --txt
HS85:ML-KEM-768:ML-DSA-65:9jqo^F*2M7/cQfB.D@-C>O5,&@e'R...
...   (255 bytes per line)
```

Paste each line between quotes as the character-strings of the
`_hs_key.<host>` TXT record, e.g.
`_hs_key.example.org. IN TXT "HS85:..." "..."`. The private key is never
exported — it stays in the encrypted `.hskey`.

---

## 📋 CLI reference

```
hs gen-key [-o PATH] [--kem ML-KEM-768] [--dsa ML-DSA-65]
           [--public-key PATH] [--no-passphrase] [--passphrase-file FILE]
           [--argon2-mem KIB] [--argon2-time N] [--argon2-par N]

hs sign FILE SELECTOR [-k KEY.hskey] [-o OUT.html]
           [--no-passphrase] [--passphrase-file FILE]

hs verify FILE|URL [-k KEY.pub|KEY.hskey] [--ignore-tls-errors]
           [--no-passphrase] [--passphrase-file FILE]

hs view-key [-k KEY.hskey] [--no-passphrase] [--passphrase-file FILE]

hs export [-k KEY.hskey] [-o KEY.pub] [--txt]
           [--no-passphrase] [--passphrase-file FILE]
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
  `data-hs-signature="SHA3-256+ML-KEM-768+ML-DSA-65+BASE64:<payload>"`
  where the payload is `kem_pk || dsa_pk || signature`.
- **Hash-then-sign** 🧬: the ML-DSA signature covers the 32-byte SHA3-256
  digest of the block's canonical bytes (marked by the `SHA3-256` entry in
  the algorithm list), so signing cost is independent of block size. Legacy
  signatures that covered the raw canonical bytes are still verified.
- **Self-contained**: the embedded public keys let `verify` work out of the
  box; trust comes from comparing fingerprints or supplying `-k`.
- **Minification-proof** 🔧: the signature is computed over a canonical form
  of the block in which text whitespace is normalized — runs collapse to a
  single space, leading/trailing whitespace is trimmed, and whitespace-only
  text nodes (indentation, line breaks) are dropped. A server can minify or
  reformat the block and every signature still validates; changing actual
  content, attributes, or structure still fails verification. Whitespace
  inside `<pre>`, `<textarea>`, `<script>`, and `<style>` is preserved
  verbatim because it is semantically significant.
- **DNS-friendly keys** 🌐: `export --txt` publishes the public key in a
  compact base-85 encoding (`HS85:<KEM>:<DSA>:<ascii85(keys)>`, no PEM
  markers, DNS-safe alphabet without `"` `\` `;` `(` `)` or whitespace) so
  the whole `_hs_key.<host>` TXT record fits between quotes and under the
  practical 4096-byte limit — ~3946 bytes for the default key, versus 4329
  with base64 armor. (PQ public keys are incompressible, so base-85's 20%
  overhead beats any compression.)
- **Memory safety**: no `unsafe`, secret material is zeroized, and all
  key material on disk is passphrase-encrypted.

## 📁 Project layout

```
src/
  lib.rs        crate-level API documentation
  cli.rs        clap CLI definitions
  crypto/       ML-KEM, ML-DSA, symmetric primitives, key file format
  ascii85.rs    compact Base85 encoding for DNS TXT public keys
  format.rs     signature attribute encoding/parsing
  html.rs       HTML parsing, signing, verification, report rendering
  keys.rs       key generation, storage, public key armor
  net.rs        HTTPS fetch + DNS `_hs_key` key resolution
  main.rs       binary entry point and command dispatch
```
