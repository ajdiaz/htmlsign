//! Binary entry point for the `hs` CLI tool.
//!
//! Parses command-line arguments via [`cli`](hs::cli), resolves the
//! passphrase for key operations, and dispatches to the appropriate
//! handler in [`keys`](hs::keys) and [`html`](hs::html).

use anyhow::{Context, Result};
use clap::Parser;
use hs::cli::{Cli, Commands};
use hs::crypto::keyfile::KdfParams;
use hs::crypto::{DsaVariant, KemVariant};
use hs::html::{self, BlockVerification, SigningKey};
use hs::keys;
use std::path::PathBuf;

/// Read a passphrase from a file (first line) or prompt interactively.
///
/// Returns `Ok(None)` when `--no-passphrase` is given.
fn resolve_passphrase(
    no_passphrase: bool,
    passphrase_file: Option<&str>,
    prompt: &str,
    confirm: bool,
) -> Result<Option<String>> {
    if no_passphrase {
        return Ok(None);
    }
    if let Some(path) = passphrase_file {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading passphrase file {}", path))?;
        let first = content.lines().next().unwrap_or_default().to_string();
        return Ok(Some(first));
    }
    let pass = rpassword::prompt_password(prompt)?;
    if confirm {
        let pass2 = rpassword::prompt_password("Confirm passphrase: ")?;
        if pass != pass2 {
            anyhow::bail!("passphrases do not match");
        }
    }
    Ok(Some(pass))
}

fn resolve_key_path(cli_path: Option<String>) -> PathBuf {
    cli_path
        .map(PathBuf::from)
        .unwrap_or_else(keys::default_key_path)
}

fn read_html(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path))
}

fn print_verification_results(results: &[BlockVerification]) -> Result<()> {
    let (report, all_ok) = html::render_report(results);
    print!("{}", report);
    let total = results.len();
    let ok = results.iter().filter(|r| r.valid).count();
    if all_ok {
        println!("OK: {} of {} blocks verified.", ok, total);
    } else {
        println!("FAIL: {} of {} blocks verified.", ok, total);
    }
    Ok(())
}

fn cmd_gen_key(args: &hs::cli::Commands) -> Result<()> {
    let Commands::GenKey {
        output,
        public_key,
        kem,
        dsa,
        no_passphrase,
        passphrase_file,
        argon2_mem,
        argon2_time,
        argon2_par,
    } = args
    else {
        unreachable!()
    };

    let kem_variant =
        KemVariant::parse(kem).with_context(|| format!("unknown KEM variant: {}", kem))?;
    let dsa_variant =
        DsaVariant::parse(dsa).with_context(|| format!("unknown DSA variant: {}", dsa))?;

    let passphrase = resolve_passphrase(
        *no_passphrase,
        passphrase_file.as_deref(),
        "Enter passphrase for new key: ",
        true,
    )?
    .unwrap_or_default();

    let out_path = output
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(keys::default_key_path);
    let params = KdfParams {
        mem_cost: *argon2_mem,
        time_cost: *argon2_time,
        par_cost: *argon2_par,
    };

    let info = keys::generate_key(&out_path, kem_variant, dsa_variant, &passphrase, &params)?;

    if let Some(pub_path) = public_key {
        let armored = keys::armor_public_key(&info);
        std::fs::write(pub_path, armored).with_context(|| format!("writing {}", pub_path))?;
        println!("Public key:  {}", pub_path);
    }

    println!("Generated key pair:");
    println!("  secret key: {}", out_path.display());
    println!("  kem: {}", info.kem_variant.as_str());
    println!("  dsa: {}", info.dsa_variant.as_str());
    println!("  fingerprint: {}", info.fingerprint);
    Ok(())
}

fn cmd_sign(args: &hs::cli::Commands) -> Result<()> {
    let Commands::Sign {
        file,
        selector,
        key,
        no_passphrase,
        passphrase_file,
        output,
    } = args
    else {
        unreachable!()
    };

    let key_path = resolve_key_path(key.clone());
    let passphrase = resolve_passphrase(
        *no_passphrase,
        passphrase_file.as_deref(),
        "Enter passphrase for signing key: ",
        false,
    )?
    .unwrap_or_default();

    let unlocked = keys::unlock_key(&key_path, &passphrase)
        .with_context(|| format!("unlocking key {}", key_path.display()))?;
    let signing_key = SigningKey {
        kem_variant: unlocked.info.kem_variant,
        dsa_variant: unlocked.info.dsa_variant,
        kem_public_key: unlocked.info.kem_public_key.clone(),
        dsa_public_key: unlocked.info.dsa_public_key.clone(),
        dsa_secret_key: unlocked.dsa_secret_key,
    };

    let html_input = read_html(file)?;
    let (signed_html, signed) = html::sign_blocks(&html_input, selector, &signing_key)
        .with_context(|| format!("signing blocks in {}", file))?;

    let out_path = output.clone().unwrap_or_else(|| file.clone());
    let mut tmp_path = out_path.clone();
    tmp_path.push_str(".hs-tmp");
    std::fs::write(&tmp_path, &signed_html).with_context(|| format!("writing {}", out_path))?;
    std::fs::rename(&tmp_path, &out_path).with_context(|| format!("writing {}", out_path))?;

    println!("Signed {} block(s) in {}", signed.len(), out_path);
    println!("  key fingerprint: {}", signed[0].fingerprint);
    for block in &signed {
        println!("  <{}> signed {} bytes", block.element, block.content_len);
    }
    Ok(())
}

fn cmd_verify(args: &hs::cli::Commands) -> Result<()> {
    let Commands::Verify { file, key } = args else {
        unreachable!()
    };

    let html_input = read_html(file)?;
    let results = html::verify_blocks(&html_input)
        .with_context(|| format!("verifying blocks in {}", file))?;

    let mut ok = true;
    if let Some(pub_path) = key {
        let armored =
            std::fs::read_to_string(pub_path).with_context(|| format!("reading {}", pub_path))?;
        let expected = keys::unarmor_public_key(&armored)
            .with_context(|| format!("parsing public key {}", pub_path))?;
        for r in &results {
            if r.fingerprint != expected.fingerprint {
                println!(
                    "[<{}>] key fingerprint mismatch: got {}",
                    r.element, r.fingerprint
                );
                ok = false;
            }
        }
    }

    print_verification_results(&results)?;
    if ok {
        Ok(())
    } else {
        anyhow::bail!("verification failed: key or content mismatch")
    }
}

fn cmd_view_key(args: &hs::cli::Commands) -> Result<()> {
    let Commands::ViewKey {
        key,
        no_passphrase,
        passphrase_file,
    } = args
    else {
        unreachable!()
    };

    let key_path = resolve_key_path(key.clone());
    let passphrase = resolve_passphrase(
        *no_passphrase,
        passphrase_file.as_deref(),
        "Enter passphrase for key: ",
        false,
    )?
    .unwrap_or_default();

    let unlocked = keys::unlock_key(&key_path, &passphrase)
        .with_context(|| format!("unlocking key {}", key_path.display()))?;

    println!("Key file: {}", key_path.display());
    println!("  kem: {}", unlocked.info.kem_variant.as_str());
    println!("  dsa: {}", unlocked.info.dsa_variant.as_str());
    println!("  fingerprint: {}", unlocked.info.fingerprint);
    print!("{}", keys::armor_public_key(&unlocked.info));
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.dry_run {
        let what = match &cli.command {
            Commands::GenKey { .. } => "gen-key",
            Commands::Sign { .. } => "sign",
            Commands::Verify { .. } => "verify",
            Commands::ViewKey { .. } => "view-key",
        };
        eprintln!("[dry-run] would {}: no action taken", what);
        return Ok(());
    }

    match &cli.command {
        Commands::GenKey { .. } => cmd_gen_key(&cli.command),
        Commands::Sign { .. } => cmd_sign(&cli.command),
        Commands::Verify { .. } => cmd_verify(&cli.command),
        Commands::ViewKey { .. } => cmd_view_key(&cli.command),
    }
}
