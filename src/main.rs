//! Binary entry point for the `hs` CLI tool.
//!
//! Parses command-line arguments via [`cli`](hs::cli), resolves the
//! passphrase for key operations, and dispatches to the appropriate
//! handler in [`keys`](hs::keys), [`html`](hs::html), and
//! [`net`](hs::net) (URL fetch + DNS key resolution for remote verify).

use anyhow::{Context, Result};
use clap::Parser;
use hs::cli::{Cli, Commands, OutputFormat};
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
    let Commands::Verify {
        file,
        key,
        ignore_tls_errors,
        no_passphrase,
        passphrase_file,
        format,
    } = args
    else {
        unreachable!()
    };

    let is_url = hs::net::is_url(file);
    let html_input = if is_url {
        eprintln!("Fetching {} ...", file);
        hs::net::fetch_html(file, *ignore_tls_errors)?
    } else {
        read_html(file)?
    };
    let results = html::verify_blocks(&html_input)
        .with_context(|| format!("verifying blocks in {}", file))?;

    let expected = if let Some(pub_path) = key {
        let key_path = PathBuf::from(pub_path);
        let passphrase = if keys::is_armored_key(&key_path)? {
            String::new()
        } else {
            resolve_passphrase(
                *no_passphrase,
                passphrase_file.as_deref(),
                "Enter passphrase for key: ",
                false,
            )?
            .unwrap_or_default()
        };
        Some(
            keys::load_public_key(&key_path, &passphrase)
                .with_context(|| format!("loading public key {}", pub_path))?,
        )
    } else if is_url {
        let host = hs::net::host_of(file)?;
        Some(hs::net::resolve_key_from_dns(&host, *ignore_tls_errors)?)
    } else {
        None
    };

    let key_matches = expected.as_ref().map(|expected| {
        results
            .iter()
            .map(|r| r.fingerprint == expected.fingerprint)
            .collect::<Vec<bool>>()
    });
    let ok = results.iter().all(|r| r.valid)
        && key_matches.as_ref().is_none_or(|km| km.iter().all(|&m| m));

    match *format {
        OutputFormat::Json => {
            let report = html::build_json_report(&results, key_matches.as_deref());
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
            if let (Some(expected), Some(matches)) = (&expected, &key_matches) {
                for (r, m) in results.iter().zip(matches) {
                    if !m {
                        println!(
                            "[<{}>] key fingerprint mismatch: got {} (expected {})",
                            r.element, r.fingerprint, expected.fingerprint
                        );
                    }
                }
            }
            print_verification_results(&results)?;
        }
    }

    if ok {
        Ok(())
    } else {
        anyhow::bail!("verification failed: key or content mismatch")
    }
}

fn cmd_export(args: &hs::cli::Commands) -> Result<()> {
    let Commands::Export {
        key,
        output,
        txt,
        url,
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
    let armored = keys::armor_public_key(&unlocked.info);

    let text = if *txt {
        let url = url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--txt requires --url"))?;
        format!("{}\n", hs::net::dns_pin(&unlocked.info, url))
    } else {
        armored
    };

    match output {
        Some(out_path) => {
            std::fs::write(out_path, &text).with_context(|| format!("writing {}", out_path))?;
            if *txt {
                println!("Exported (DNS pin record): {}", out_path);
            } else {
                println!("Exported (armored public key): {}", out_path);
            }
            println!("  fingerprint: {}", unlocked.info.fingerprint);
        }
        None => print!("{}", text),
    }
    Ok(())
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
            Commands::Export { .. } => "export",
        };
        eprintln!("[dry-run] would {}: no action taken", what);
        return Ok(());
    }

    match &cli.command {
        Commands::GenKey { .. } => cmd_gen_key(&cli.command),
        Commands::Sign { .. } => cmd_sign(&cli.command),
        Commands::Verify { .. } => cmd_verify(&cli.command),
        Commands::ViewKey { .. } => cmd_view_key(&cli.command),
        Commands::Export { .. } => cmd_export(&cli.command),
    }
}
