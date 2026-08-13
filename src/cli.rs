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
    about = "Sign and verify blocks of HTML with post-quantum cryptography"
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
    #[command(name = "gen-key")]
    GenKey {
        /// Where to write the secret key file.
        #[arg(
            short = 'o',
            long = "output",
            help = "Output path for the secret key file"
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
    #[command(name = "sign")]
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
        #[arg(short = 'o', long = "output", help = "Output HTML file path")]
        output: Option<String>,
    },
    /// Verify signed blocks in an HTML file.
    #[command(name = "verify")]
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
    #[command(name = "export")]
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
    #[command(name = "view-key")]
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
