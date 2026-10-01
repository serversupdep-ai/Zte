mod dvar;
mod hp;
mod identify;
mod sivb;
mod tui;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "dellpwn",
    about = "Dell BIOS security research tool",
    version = VERSION,
    after_help = "Run without arguments for interactive TUI mode."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan firmware image and recover BIOS passwords
    Scan {
        /// Path to SPI flash dump
        image: PathBuf,

        /// Show hex details of stored/key bytes
        #[arg(long)]
        raw: bool,

        /// Include partial recovery results (noisy, for manual analysis)
        #[arg(long)]
        partial: bool,
    },

    /// Clear SIVB block to revert password (creates modified copy)
    #[command(name = "clear-sivb")]
    ClearSivb {
        /// Input SPI flash dump
        input: PathBuf,

        /// Output path for modified dump
        output: PathBuf,
    },

    /// Clear E7250-style password store + Setup flags (creates modified copy)
    #[command(name = "clear-password")]
    ClearPassword {
        /// Input SPI flash dump
        input: PathBuf,

        /// Output path for modified dump
        output: PathBuf,
    },

    /// Deactivate HP NVAR password entries (t530-style jumper reset)
    #[command(name = "clear-hp-password")]
    ClearHpPassword {
        /// Input SPI flash dump
        input: PathBuf,

        /// Output path for modified dump
        output: PathBuf,
    },
}

fn read_image(path: &PathBuf) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(data) => {
            eprintln!(
                "File: {} ({} bytes / {}KB)",
                path.display(),
                data.len(),
                data.len() / 1024
            );
            data
        }
        Err(e) => {
            eprintln!("Error: failed to read {}: {}", path.display(), e);
            process::exit(1);
        }
    }
}

fn cmd_scan(image: PathBuf, raw: bool, partial: bool) {
    let data = read_image(&image);

    // BIOS identification
    let id = identify::identify(&data);
    print!("{}", identify::format_identification(&id));
    println!();

    // Report security artifacts
    print!("{}", sivb::scan_report(&data));
    println!();

    // HP password hashes
    if hp::is_hp_firmware(&data) {
        println!("--- HP Password Hashes ---\n");
        let hashes = hp::find_hashes(&data);
        print!("{}", hp::format_results(&hashes));
        println!();
    }

    // Dell DVAR password recovery (only if DVAR store exists)
    if let Some((dvar_start, dvar_end)) = dvar::find_dvar_region(&data) {
        println!("--- Dell Password Recovery ---\n");
        eprintln!("DVAR store: 0x{:06x} - 0x{:06x}", dvar_start, dvar_end);
        let records = dvar::scan_for_passwords(&data, dvar_start, dvar_end, partial);
        if raw {
            print!("{}", dvar::format_results_raw(&records));
        } else {
            print!("{}", dvar::format_results(&records));
        }
    }
}

fn cmd_clear_sivb(input: PathBuf, output: PathBuf) {
    let data = read_image(&input);

    match sivb::clear_sivb(&data) {
        Some(result) => {
            for change in &result.changes {
                eprintln!("[*] {}", change);
            }

            match std::fs::write(&output, &result.modified) {
                Ok(()) => {
                    eprintln!("\n[*] Written to {}", output.display());
                }
                Err(e) => {
                    eprintln!("\n[!] Error writing output: {}", e);
                    process::exit(1);
                }
            }
        }
        None => {
            eprintln!("[!] No SIVB block found in image.");
            process::exit(1);
        }
    }
}

fn cmd_clear_password(input: PathBuf, output: PathBuf) {
    let data = read_image(&input);

    match sivb::clear_password_e7250(&data) {
        Some(result) => {
            for change in &result.changes {
                eprintln!("[*] {}", change);
            }

            match std::fs::write(&output, &result.modified) {
                Ok(()) => {
                    eprintln!("\n[*] Written to {}", output.display());
                }
                Err(e) => {
                    eprintln!("\n[!] Error writing output: {}", e);
                    process::exit(1);
                }
            }
        }
        None => {
            eprintln!("[!] No E7250-style password store found in image.");
            process::exit(1);
        }
    }
}

fn cmd_clear_hp_password(input: PathBuf, output: PathBuf) {
    let data = read_image(&input);

    match hp::clear_hp_password(&data) {
        Some(result) => {
            for change in &result.changes {
                eprintln!("[*] {}", change);
            }

            match std::fs::write(&output, &result.modified) {
                Ok(()) => {
                    eprintln!("\n[*] Written to {}", output.display());
                }
                Err(e) => {
                    eprintln!("\n[!] Error writing output: {}", e);
                    process::exit(1);
                }
            }
        }
        None => {
            eprintln!("[!] No HP password entries found (or all already cleared).");
            process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { image, raw, partial }) => cmd_scan(image, raw, partial),
        Some(Commands::ClearSivb { input, output }) => cmd_clear_sivb(input, output),
        Some(Commands::ClearPassword { input, output }) => cmd_clear_password(input, output),
        Some(Commands::ClearHpPassword { input, output }) => cmd_clear_hp_password(input, output),
        None => {
            // TUI mode
            if let Err(e) = tui::run() {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    }
}
