// nmdns — mDNS responder, cache, and cross-interface repeater.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use nmdns::config::Resolved;
use nmdns::{engine, exit_code, services};

/// mDNS responder, cache, and cross-interface repeater
#[derive(Parser, Debug)]
#[command(name = "nmdns", about, long_about = None)]
struct Cli {
    /// Path to TOML config
    #[arg(short = 'c', long, default_value = "/etc/nmdns.toml")]
    config: PathBuf,

    /// Parse and validate the config, then exit
    #[arg(long)]
    check: bool,
}

fn install_logging() {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_target(false)
        .init();
}

fn main() {
    let cli = Cli::parse();

    let cfg = match Resolved::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nmdns: {e}");
            process::exit(exit_code::CONFIG);
        }
    };

    if cli.check {
        // Run the same name-parsing the daemon would do at startup so
        // bad service/instance/host labels and bad browse targets fail
        // `--check` instead of crashing the unit at first start.
        let hostname = services::resolve_hostname(&cfg.hostname);
        if let Err(e) = services::validate(&hostname, &cfg.services) {
            eprintln!("nmdns: {e}");
            process::exit(exit_code::CONFIG_VALIDATION);
        }
        for b in &cfg.browse {
            if let Err(e) = hickory_proto::rr::Name::from_str(b) {
                eprintln!("nmdns: invalid browse target {b}: {e}");
                process::exit(exit_code::CONFIG_VALIDATION);
            }
        }
        println!(
            "nmdns: config OK ({} interface(s), {} service(s), {} browse target(s))",
            cfg.interfaces.len(),
            cfg.services.len(),
            cfg.browse.len(),
        );
        process::exit(exit_code::OK);
    }

    install_logging();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nmdns: tokio runtime: {e}");
            process::exit(exit_code::RUNTIME);
        }
    };
    let exit_code = rt.block_on(engine::run(cfg));
    process::exit(exit_code);
}
