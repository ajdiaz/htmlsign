//! Regenerate shell completions and the man page from the CLI definition.
//!
//! Run with `cargo run --example gen_docs` from the repository root. The
//! generated files are committed so end users do not need a build-time
//! toolchain:
//!
//! - `completions/hs.bash`, `completions/hs.zsh`, `completions/hs.fish`
//! - `man/hs.1`
//!
//! Every CLI change must regenerate these files and commit them together
//! with the source change.

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use hs::cli::Cli;
use std::fs;

/// Write a shell completion script.
fn write_completion(shell: clap_complete::Shell, path: &str) {
    let mut cmd = Cli::command();
    let mut content = Vec::new();
    generate(shell, &mut cmd, "hs", &mut content);
    fs::write(path, content).expect("write completion file");
    println!("wrote {}", path);
}

/// Write the roff man page for a command.
fn write_man(cmd: &clap::Command, path: &str) {
    let man = clap_mangen::Man::new(cmd.clone());
    let mut content = Vec::new();
    man.render(&mut content).expect("render man page");
    fs::write(path, content).expect("write man page");
    println!("wrote {}", path);
}

/// Render a command and all its subcommands as separate man pages.
fn render_man_tree(cmd: &clap::Command, prefix: &str) {
    let path = format!("man/{}.1", prefix);
    write_man(cmd, &path);
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        render_man_tree(sub, &format!("{}-{}", prefix, name));
    }
}

/// Ensure a directory exists.
fn ensure_dir(path: &str) {
    fs::create_dir_all(path).expect("create directory");
}

fn main() {
    ensure_dir("completions");
    write_completion(Shell::Bash, "completions/hs.bash");
    write_completion(Shell::Zsh, "completions/hs.zsh");
    write_completion(Shell::Fish, "completions/hs.fish");

    ensure_dir("man");
    render_man_tree(&Cli::command(), "hs");
}
