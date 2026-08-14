//! CLI interface definitions using `clap`.
//!
//! Defines the [`Cli`] entry point and [`Commands`] enum with all
//! subcommands. This module is purely structural — command dispatch
//! and business logic live in `src/main.rs`.

use clap::{Parser, Subcommand, ValueEnum};

/// Output format for the `verify` command's report.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text report.
    Text,
    /// Machine-readable JSON report.
    Json,
}

/// Top-level CLI structure for the `hs` binary.
#[derive(Parser)]
#[command(
    name = "hs",
    version,
    about = "Sign and verify blocks of HTML with post-quantum cryptography",
    long_about = "Sign and verify blocks of HTML (SGML/XML in general) with post-quantum cryptography.

hs embeds a self-contained, post-quantum signature into a data-hs-signature
attribute on matching HTML blocks, so content can be verified after it has
crossed the network — a TLS connection authenticates the endpoint, but the
served content itself is bound to the signature. Verification checks each
block against a supplied key: from verify -k, the default key file, or the
_hs_key.<host> DNS pin record."
)]
pub struct Cli {
    /// Print a dry-run message and exit without doing anything.
    #[arg(
        short = 'n',
        long = "dry-run",
        global = true,
        help = "Do nothing, print dry-run message"
    )]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// All subcommands supported by `hs`.
#[derive(Subcommand)]
pub enum Commands {
    /// Generate a key pair (ML-KEM + ML-DSA), passphrase-encrypted.
    #[command(
        name = "gen-key",
        long_about = "Generate an ML-KEM + ML-DSA key pair and store the secret key at the
given output path (default ~/.local/share/hs/keys/default.hskey), encrypted
at rest with Argon2id + XChaCha20-Poly1305 and 0600 permissions.

The passphrase is prompted twice (create + confirm) unless --no-passphrase
or --passphrase-file is given. With --public-key, the armored public key is
also written to the given path."
    )]
    GenKey {
        /// Where to write the secret key file.
        #[arg(
            short = 'o',
            long = "output",
            help = "Output path for the secret key file (default: ~/.local/share/hs/keys/default.hskey)"
        )]
        output: Option<String>,
        /// Also write the armored public key to this path.
        #[arg(
            long = "public-key",
            help = "Write the armored public key to this path"
        )]
        public_key: Option<String>,
        /// KEM variant to generate.
        #[arg(
            long = "kem",
            default_value = "ML-KEM-768",
            help = "KEM algorithm variant: ML-KEM-512, ML-KEM-768, ML-KEM-1024"
        )]
        kem: String,
        /// DSA variant to generate.
        #[arg(
            long = "dsa",
            default_value = "ML-DSA-65",
            help = "Digital signature variant: ML-DSA-44, ML-DSA-65, ML-DSA-87"
        )]
        dsa: String,
        /// Use an empty passphrase (no prompt).
        #[arg(long = "no-passphrase", help = "Store the key without a passphrase")]
        no_passphrase: bool,
        /// Read the passphrase from a file instead of prompting.
        #[arg(
            long = "passphrase-file",
            help = "Read the passphrase from a file (first line)"
        )]
        passphrase_file: Option<String>,
        /// Argon2id memory cost in KiB.
        #[arg(
            long = "argon2-mem",
            default_value = "65536",
            help = "Argon2id memory cost in KiB (default 65536 ~= 64 MiB)"
        )]
        argon2_mem: u32,
        /// Argon2id time cost.
        #[arg(
            long = "argon2-time",
            default_value = "3",
            help = "Argon2id time cost / iterations (default 3)"
        )]
        argon2_time: u32,
        /// Argon2id parallelism.
        #[arg(
            long = "argon2-par",
            default_value = "1",
            help = "Argon2id parallelism / threads (default 1)"
        )]
        argon2_par: u32,
    },
    /// Sign HTML blocks matching a CSS selector.
    #[command(
        name = "sign",
        long_about = "Find every element matching SELECTOR (full CSS selectors, e.g.
div.text, #price, article[data-id=\"42\"]), remove any existing
data-hs-signature, sign the SHA3-256 digest of the block's canonical
serialization — whitespace-normalized so signatures survive server-side
minification — and inject the new signature attribute.

The output is written to --output, or back over FILE in place. The secret
key defaults to ~/.local/share/hs/keys/default.hskey (override with -k);
its passphrase is prompted unless --no-passphrase or --passphrase-file is
given.

A block that already sits inside another signed block is skipped (it is
covered by the enclosing signature); skipped blocks are reported and left
untouched."
    )]
    Sign {
        /// Input HTML file.
        #[arg(value_name = "FILE", help = "HTML file to sign")]
        file: String,
        /// CSS selector of blocks to sign.
        #[arg(value_name = "SELECTOR", help = "CSS selector of the block(s) to sign")]
        selector: String,
        /// Secret key file.
        #[arg(
            short = 'k',
            long = "key",
            help = "Path to the secret key file (.hskey)"
        )]
        key: Option<String>,
        /// Use an empty passphrase (no prompt).
        #[arg(long = "no-passphrase", help = "Use an empty passphrase (no prompt)")]
        no_passphrase: bool,
        /// Read the passphrase from a file instead of prompting.
        #[arg(
            long = "passphrase-file",
            help = "Read the passphrase from a file (first line)"
        )]
        passphrase_file: Option<String>,
        /// Write the signed HTML to this path instead of overwriting the input.
        #[arg(
            short = 'o',
            long = "output",
            help = "Output HTML file path (default: overwrite FILE)"
        )]
        output: Option<String>,
    },
    /// Verify signed blocks in an HTML file.
    #[command(
        name = "verify",
        long_about = "Locate every block carrying a data-hs-signature attribute, recompute its
canonical bytes, and check the ML-DSA signature against the supplied key.
The command exits non-zero if any block is invalid.

The key is taken from -k (an armored key.pub or a .hskey secret key file
unlocked with the passphrase), from the default key file when verifying a
local file without -k, or from the _hs_key.<host> DNS pin record when FILE
is a URL.

When FILE is an http:// or https:// URL, the document is fetched over
HTTPS (validating the TLS certificate unless --ignore-tls-errors is given)
and the signing key is resolved from the _hs_key.<host> DNS pin record,
downloading the key and checking its SHA3-256 fingerprint against the pin.

--format json emits a machine-readable report (ok, total, verified, key
origin, per-block results, and warnings) instead of the human-readable text
report. A signed block nested inside another signed block is reported as a
warning (\"<inner> in line N is outside <outer> signature\") — its subtree
is excluded from the outer signature and it is verified separately."
    )]
    Verify {
        /// Input HTML file, or an http(s) URL to fetch and verify.
        #[arg(value_name = "FILE|URL", help = "HTML file or URL to verify")]
        file: String,
        /// Restrict verification to a specific public key.
        ///
        /// Accepts either an armored public key file (`key.pub`) or a
        /// `.hskey` secret key file (unlocked with the passphrase).
        #[arg(
            short = 'k',
            long = "key",
            help = "Require blocks to be signed with this public key (armored or .hskey)"
        )]
        key: Option<String>,
        /// Do not validate the TLS certificate when fetching a URL.
        #[arg(
            long = "ignore-tls-errors",
            help = "Skip TLS certificate validation when verifying a URL"
        )]
        ignore_tls_errors: bool,
        /// Output format of the verification report.
        #[arg(
            long = "format",
            value_enum,
            default_value_t = OutputFormat::Text,
            help = "Output format: text (default) or json"
        )]
        format: OutputFormat,
        /// Use an empty passphrase (no prompt).
        #[arg(long = "no-passphrase", help = "Use an empty passphrase (no prompt)")]
        no_passphrase: bool,
        /// Read the passphrase from a file instead of prompting.
        #[arg(
            long = "passphrase-file",
            help = "Read the passphrase from a file (first line)"
        )]
        passphrase_file: Option<String>,
    },
    /// Export the public key of a key file (armored, or a DNS pin record).
    #[command(
        name = "export",
        long_about = "Unlock a key file and print its armored public key
(-----BEGIN HS PUBLIC KEY-----) for out-of-band distribution or for serving
at a well-known URL. The private key is never exported — it stays in the
encrypted .hskey file.

With --txt --url <URL>, emit the DNS pin record instead:
HSPIN:SHA3-256:<fingerprint>:<url>. Publish that single short line as the
_hs_key.<host> TXT record and serve the armored public key at <url>;
remote verification downloads the key and requires its fingerprint to
match the pin."
    )]
    Export {
        /// Secret key file.
        #[arg(
            short = 'k',
            long = "key",
            help = "Path to the secret key file (.hskey)"
        )]
        key: Option<String>,
        /// Write the public key to this file instead of stdout.
        #[arg(
            short = 'o',
            long = "output",
            help = "Write the public key to this file"
        )]
        output: Option<String>,
        /// URL where the public key will be served (for the DNS pin record).
        #[arg(
            long = "url",
            help = "URL of the public key to publish in the _hs_key DNS pin record"
        )]
        url: Option<String>,
        /// Emit the DNS pin record (SHA3-256 fingerprint + key URL).
        #[arg(
            long = "txt",
            requires = "url",
            help = "Output the HSPIN:SHA3-256:<fingerprint>:<url> DNS TXT record (requires --url)"
        )]
        txt: bool,
        /// Use an empty passphrase (no prompt).
        #[arg(long = "no-passphrase", help = "Use an empty passphrase (no prompt)")]
        no_passphrase: bool,
        /// Read the passphrase from a file instead of prompting.
        #[arg(
            long = "passphrase-file",
            help = "Read the passphrase from a file (first line)"
        )]
        passphrase_file: Option<String>,
    },
    /// Display information about a key file.
    #[command(
        name = "view-key",
        long_about = "Unlock a key file (default ~/.local/share/hs/keys/default.hskey, override
with -k) and print its algorithm variants, fingerprint, and path, followed
by the armored public key. The passphrase is prompted unless
--no-passphrase or --passphrase-file is given."
    )]
    ViewKey {
        /// Secret key file.
        #[arg(
            short = 'k',
            long = "key",
            help = "Path to the secret key file (.hskey)"
        )]
        key: Option<String>,
        /// Use an empty passphrase (no prompt).
        #[arg(long = "no-passphrase", help = "Use an empty passphrase (no prompt)")]
        no_passphrase: bool,
        /// Read the passphrase from a file instead of prompting.
        #[arg(
            long = "passphrase-file",
            help = "Read the passphrase from a file (first line)"
        )]
        passphrase_file: Option<String>,
    },
}
