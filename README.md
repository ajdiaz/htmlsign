# 🔐 hs — sign & verify HTML blocks with post-quantum cryptography

`hs` signs **blocks** of an HTML (SGML/XML) document and lets anyone verify
them — even after the bytes have crossed the network. A TLS connection can
prove *who* you are talking to, but it can't prove the *content* they serve
is the content you intended. `hs` freezes the exact bytes of a block into a
self-contained, post-quantum signature attribute.

```html
<div class="text" data-hs-signature="SHA3-256+ML-DSA-65+BASE64:QWsd....">
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
- The signature is a plain ML-DSA signature — the **public key is not
  embedded**. Verification always uses a key you supply: `verify -k
  key.pub`, the default key file, or the key pinned in the `_hs_key.<host>`
  DNS record for URL verification.
- **Verify** finds every signed block, recomputes its canonical bytes, and
  checks the ML-DSA signature against that key.
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

Verify a local file against the **default key** (`~/.local/share/hs/keys/default.hskey`):

```bash
$ hs verify index.html
key: /home/user/.local/share/hs/keys/default.hskey
[0] <div> OK
      fingerprint: 7f6a2c...c3d09b
OK: 1 of 1 blocks verified.
```

Verify against a specific key with `-k`:

```bash
$ hs verify index.html -k key.pub
key: key.pub
[0] <div> OK
```

`-k` accepts **either** an armored public key file (`key.pub`) **or** the
`.hskey` secret key file itself — the tool detects the format and unlocks
the secret key (prompting for its passphrase) to use its public half. The
`key:` line reports where the key used for verification came from (a file
or the DNS pin record).

Tampered content fails loudly:

```bash
$ hs verify tampered.html
key: /home/user/.local/share/hs/keys/default.hskey
[0] <div> FAIL
      reason: signature does not match block content
FAIL: 0 of 1 blocks verified.
```

For automation, `--format json` emits the result as machine-readable JSON —
with `ok`, `total`, `verified`, a `key` object describing where the key is
located (`source` is `file` or `dns`), and a `blocks` array (each entry has
`element`, `valid`, `fingerprint`, and `reason`):

```bash
$ hs verify index.html -k key.pub --format json
{
  "ok": true,
  "total": 1,
  "verified": 1,
  "key": { "source": "file", "location": "key.pub" },
  "blocks": [
    {
      "element": "div",
      "valid": true,
      "fingerprint": "7f6a2c...c3d09b",
      "reason": null
    }
  ]
}
```

The exit status is non-zero whenever the verification fails (any invalid
block), so `hs verify --format json` drops straight into a CI pipeline.

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
2. Reads the DNS TXT record `_hs_key.example.org`, which **pins** the
   signing key: it holds the key's SHA3-256 fingerprint and the URL where
   the key is served. `hs` downloads the key from that URL and requires its
   fingerprint to match the pin exactly, then requires every signed block
   to match that key.

Publish the pin record from `hs export -k key.hskey --txt --url <URL>` at
`_hs_key.<your-domain>` and serve the armored public key (`hs export -k
key.hskey -o key.pub`) at `<URL>`. This closes the gap TLS leaves open: TLS
authenticates the *endpoint*, the `_hs_key` pin authenticates the *key*, and
the signature binds the *content*.

### 📤 Exporting a key for DNS

Export the public key of an existing key file without regenerating anything.
Without `--txt`, the armored form is printed for out-of-band distribution
or for serving at a well-known URL:

```bash
$ hs export -k ~/.local/share/hs/keys/default.hskey
-----BEGIN HS PUBLIC KEY-----
ML-KEM-768 ML-DSA-65
...
-----END HS PUBLIC KEY-----
```

Serve the armored public key at a URL (e.g. `https://example.org/.well-known/hs.pub`),
then print the DNS pin record that ties that URL to the key's fingerprint
with `--txt --url`:

```bash
$ hs export -k key.hskey --txt --url https://example.org/.well-known/hs.pub
HSPIN:SHA3-256:7f6a2c...c3d09b:https://example.org/.well-known/hs.pub
```

Paste that single short line as the `_hs_key.<host>` TXT record — it is
well under the 255-byte character-string limit. `hs verify <URL>` downloads
the key, checks its SHA3-256 fingerprint against the pin, and fails loudly
on any mismatch. Write to a file with `-o`. The private key is never
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
           [--format text|json]
           [--no-passphrase] [--passphrase-file FILE]

hs view-key [-k KEY.hskey] [--no-passphrase] [--passphrase-file FILE]

hs export [-k KEY.hskey] [-o KEY.pub] [--txt --url URL]
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
  `data-hs-signature="SHA3-256+ML-DSA-65+BASE64:<signature>"` — the payload
  is the ML-DSA signature only; the public key is **not** embedded.
- **Hash-then-sign** 🧬: the ML-DSA signature covers the 32-byte SHA3-256
  digest of the block's canonical bytes (marked by the `SHA3-256` entry in
  the algorithm list), so signing cost is independent of block size. Legacy
  signatures that covered the raw canonical bytes are still verified.
- **Key supplied at verify time** 🔑: the trust anchor is the key you give
  `hs verify` (`-k`, the default key file, or the `_hs_key.<host>` DNS
  pin). Nothing about the document is trusted; the key binds the content.
- **Minification-proof** 🔧: the signature is computed over a canonical form
  of the block in which text whitespace is normalized — runs collapse to a
  single space, leading/trailing whitespace is trimmed, and whitespace-only
  text nodes (indentation, line breaks) are dropped. A server can minify or
  reformat the block and every signature still validates; changing actual
  content, attributes, or structure still fails verification. Whitespace
  inside `<pre>`, `<textarea>`, `<script>`, and `<style>` is preserved
  verbatim because it is semantically significant.
- **DNS-pinned keys** 🌐: remote verification pins the key's SHA3-256
  fingerprint in the `_hs_key.<host>` TXT record and downloads the key from
  the pinned URL, validating the digest on every check. The record is a
  short `HSPIN:SHA3-256:<fingerprint>:<url>` line — no 4096-byte limit, no
  quoting pitfalls — and a compromised server cannot swap in a different
  key without the pin failing.
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
