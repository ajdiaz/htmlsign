//! Library crate for `hs` — sign and verify blocks of HTML (SGML/XML in
//! general) with post-quantum cryptography.
//!
//! `hs` embeds a self-contained signature into a `data-hs-signature`
//! attribute on matching HTML blocks. A TLS connection can authenticate
//! the *endpoint* of a connection but not the *content* it serves; a
//! malicious actor who can modify the source code would go unnoticed.
//! `hs` lets you freeze the exact bytes of a block and detect any change
//! after it was signed.
//!
//! # Signature attribute format
//!
//! ```text
//! data-hs-signature="ML-KEM-768+ML-DSA-65+BASE64:<base64 payload>"
//! ```
//!
//! The payload is `kem_pk || dsa_pk || signature`. The embedded public
//! keys make every signature self-contained: `verify` works out of the
//! box, and the key fingerprint lets you confirm *who* signed the block.
//!
//! # Commands
//!
//! | Command | Description |
//! |---|---|
//! | [`gen-key`](cli::Commands::GenKey) | Generate a passphrase-encrypted key pair |
//! | [`sign`](cli::Commands::Sign) | Sign blocks matching a CSS selector |
//! | [`verify`](cli::Commands::Verify) | Verify blocks carrying `data-hs-signature` |
//! | [`view-key`](cli::Commands::ViewKey) | Show the fingerprint and algorithms of a key file |
//! | [`export`](cli::Commands::Export) | Export the armored public key (for DNS TXT records) |
//!
//! ## `gen-key`
//!
//! `hs gen-key [-o PATH] [--kem ML-KEM-768] [--dsa ML-DSA-65] [--no-passphrase] [--passphrase-file FILE] [--public-key PATH] [--argon2-mem KIB] [--argon2-time N] [--argon2-par N]`
//!
//! Generates an ML-KEM + ML-DSA key pair. The secret key is written to
//! `<output>` (default `~/.local/share/hs/keys/default.hskey`), always
//! encrypted at rest with Argon2id + XChaCha20-Poly1305 and `0o600`
//! permissions. Unless `--no-passphrase` or `--passphrase-file` is given,
//! the passphrase is prompted twice (create + confirm).
//!
//! | Flag | Description |
//! |---|---|
//! | `-o`, `--output` | Secret key file path (default: `~/.local/share/hs/keys/default.hskey`) |
//! | `--public-key` | Also write the armored public key to this path |
//! | `--kem` | `ML-KEM-512`, `ML-KEM-768` (default), `ML-KEM-1024` |
//! | `--dsa` | `ML-DSA-44`, `ML-DSA-65` (default), `ML-DSA-87` |
//! | `--no-passphrase` | Store the key with an empty passphrase |
//! | `--passphrase-file` | Read the passphrase from the first line of a file |
//! | `--argon2-mem` | Argon2id memory cost in KiB (default 65536) |
//! | `--argon2-time` | Argon2id time cost / iterations (default 3) |
//! | `--argon2-par` | Argon2id parallelism (default 1) |
//!
//! ## `sign`
//!
//! `hs sign FILE SELECTOR [-k PATH] [-o PATH] [--no-passphrase] [--passphrase-file FILE]`
//!
//! Finds every element matching `SELECTOR` (full CSS selectors supported,
//! e.g. `div.text`, `#price`, `article[data-id="42"]`), removes any
//! existing `data-hs-signature`, signs the canonical serialization of the
//! block, and injects the new signature attribute. The output is written
//! to `--output` or back over `FILE` in place.
//!
//! The secret key defaults to `~/.local/share/hs/keys/default.hskey`;
//! use `-k`/`--key` to pick another. The passphrase is prompted unless
//! `--no-passphrase` or `--passphrase-file` is given.
//!
//! ## `verify`
//!
//! `hs verify FILE|URL [-k PUBLIC_KEY_FILE] [--ignore-tls-errors] [--no-passphrase] [--passphrase-file FILE]`
//!
//! Locates every block with a `data-hs-signature` attribute, recomputes
//! its canonical bytes, and checks the embedded ML-DSA signature. Exits
//! non-zero if any block fails. With `-k`/`--key`, blocks are additionally
//! required to have been signed by exactly the given public key (defeating
//! re-signing of altered content with a different key). `-k` accepts
//! **either** an armored public key file (`key.pub`) **or** a `.hskey`
//! secret key file, which is unlocked with the passphrase (prompted
//! unless `--no-passphrase` or `--passphrase-file` is given).
//!
//! When the input is an `http://` or `https://` URL, the document is
//! fetched over HTTPS — verifying the TLS certificate unless
//! `--ignore-tls-errors` is given — and the signing public key is resolved
//! automatically from the DNS TXT record `_hs_key.<host>`, which holds the
//! armored public key. This closes the gap left by TLS: the connection is
//! authenticated, and the *content* is now pinned to the key published in
//! DNS.
//!
//! ## `view-key`
//!
//! `hs view-key [-k PATH] [--no-passphrase] [--passphrase-file FILE]`
//!
//! Unlocks a key file and prints its algorithms, fingerprint, and paths.
//!
//! ## `export`
//!
//! `hs export [-k PATH] [-o PATH] [--txt] [--no-passphrase] [--passphrase-file FILE]`
//!
//! Unlocks a key file and outputs its **armored public key**
//! (`-----BEGIN HS PUBLIC KEY-----` block). This is exactly the payload to
//! publish in the `_hs_key.<host>` DNS TXT record that remote verification
//! reads. The secret key is never exported — it stays in the encrypted
//! `.hskey` file.
//!
//! With `--txt`, the armor is first collapsed to a single line and then
//! split into DNS TXT character-strings of at most 255 bytes each, one per
//! line, so it can be pasted directly as the strings of a TXT record. The
//! record's strings are concatenated on lookup, and the parser tolerates
//! the split (see [`keys::unarmor_public_key`]).
//!
//! # Global flags
//!
//! | Flag | Description |
//! |---|---|
//! | `-n`, `--dry-run` | Print `[dry-run] would <command>: no action taken` to stderr and exit 0 without doing anything |
//! | `-h`, `--help` | Print help |
//! | `-V`, `--version` | Print version |
//!
//! # Security model
//!
//! - Secret keys are never stored raw; they are encrypted with
//!   Argon2id (default 64 MiB, 3 iterations) + XChaCha20-Poly1305.
//! - The signature binds the exact serialized bytes of the block, so
//!   any change to the block content (text, attributes, structure)
//!   invalidates the signature.
//! - Verification is self-contained: the public key is embedded in the
//!   attribute. Out-of-band trust comes from comparing fingerprints or
//!   supplying a public key with `verify -k` (armored or `.hskey`).
//! - All randomness comes from [`rand::rngs::OsRng`]; secret material is zeroized.
//!
//! # Cryptography
//!
//! - **ML-KEM** (CRYSTALS-Kyber, FIPS 203) via the `ml-kem` crate.
//! - **ML-DSA** (CRYSTALS-Dilithium, FIPS 204) via the `ml-dsa` crate.
//! - **XChaCha20-Poly1305** (RFC 8439) via `chacha20poly1305`.
//! - **Argon2id** (RFC 9106) via the `argon2` crate.
//! - **SHA3-256** (FIPS 202) via the `sha3` crate.
//!
//! The `pqcrypto` umbrella crate is deliberately avoided
//! (RUSTSEC-2026-0164, unmaintained).

pub mod cli;
pub mod crypto;
pub mod format;
pub mod html;
pub mod keys;
pub mod net;
