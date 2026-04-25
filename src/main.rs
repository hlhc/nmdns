// nmdns — mDNS responder, cache, and cross-interface repeater.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use nmdns::config::Resolved;
use nmdns::{daemon, engine, services};

/// mDNS responder, cache, and cross-interface repeater
#[derive(Parser, Debug)]
#[command(name = "nmdns", about, long_about = None)]
struct Cli {
    /// Path to TOML config
    #[arg(short = 'c', long, default_value = "/etc/nmdns.toml")]
    config: PathBuf,

    /// Run in foreground (log to stderr)
    #[arg(short = 'f', long)]
    foreground: bool,

    /// Parse and validate the config, then exit
    #[arg(long)]
    check: bool,
}

fn install_logging(foreground: bool) {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if foreground {
        tracing_subscriber::fmt()
            .with_env_filter(env)
            .with_target(false)
            .init();
    } else {
        match syslog_tracing::Syslog::new(
            c"nmdns",
            syslog_tracing::Options::LOG_PID,
            syslog_tracing::Facility::Daemon,
        ) {
            Some(syslog) => {
                tracing_subscriber::fmt()
                    .with_env_filter(env)
                    .with_writer(syslog)
                    .with_target(false)
                    .with_ansi(false)
                    .without_time()
                    .init();
            }
            None => {
                tracing_subscriber::fmt()
                    .with_env_filter(env)
                    .with_target(false)
                    .init();
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let cfg = match Resolved::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nmdns: {e}");
            process::exit(1);
        }
    };

    if cli.check {
        // Run the same name-parsing the daemon would do at startup so
        // bad service/instance/host labels and bad browse targets fail
        // `--check` instead of crashing the unit at first start.
        let hostname = services::resolve_hostname(&cfg.hostname);
        if let Err(e) = services::validate(&hostname, &cfg.services) {
            eprintln!("nmdns: {e}");
            process::exit(1);
        }
        for b in &cfg.browse {
            if let Err(e) = hickory_proto::rr::Name::from_str(b) {
                eprintln!("nmdns: invalid browse target {b}: {e}");
                process::exit(1);
            }
        }
        println!(
            "nmdns: config OK ({} interface(s), {} service(s), {} browse target(s))",
            cfg.interfaces.len(),
            cfg.services.len(),
            cfg.browse.len(),
        );
        process::exit(0);
    }

    let foreground = cli.foreground || cfg.foreground;
    let pid_file_path = cfg.pid_file.clone();

    let mut wrote_pidfile = false;
    if !foreground {
        if let Some(pid) = daemon::already_running(&cfg.pid_file) {
            eprintln!("nmdns: already running as pid {pid}");
            process::exit(1);
        }
        if let Err(e) = daemon::daemonize(&cfg.pid_file) {
            eprintln!("nmdns: daemonize: {e}");
            process::exit(1);
        }
        wrote_pidfile = true;
    }

    install_logging(foreground);

    // Build the multi-threaded runtime *after* daemonize -- fork must not
    // happen with a tokio runtime alive (it would copy worker threads).
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nmdns: tokio runtime: {e}");
            process::exit(1);
        }
    };
    let exit_code = rt.block_on(engine::run(cfg));
    if wrote_pidfile {
        let _ = std::fs::remove_file(&pid_file_path);
    }
    process::exit(exit_code);
}
