//! End-to-end CLI tests.
//!
//! These exercise the daemon binary's command-line surface: argument
//! parsing, help text, error exit codes, and `--check` config validation.
//! They do not bind sockets or join multicast — that is covered by the
//! library-level integration tests in `tests/features.rs`.

use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

fn write_config(body: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write tempfile");
    f
}

fn nmdns() -> Command {
    Command::cargo_bin("nmdns").expect("binary")
}

const VALID_CFG: &str = r#"
foreground = true
interfaces = ["lo0"]
repeat = false
hostname = "test-router"
browse = ["_http._tcp.local."]

[[service]]
name    = "Test HTTP"
service = "_http._tcp.local."
port    = 8080
txt     = ["path=/", "version=1"]
"#;

#[test]
fn help_flag_prints_usage_and_exits_zero() {
    nmdns()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("nmdns"));
}

#[test]
fn long_help_flag_works() {
    nmdns()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--check"));
}

#[test]
fn unknown_argument_exits_two_and_shows_usage() {
    nmdns()
        .arg("--bogus")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn dash_c_without_value_exits_two() {
    nmdns()
        .arg("-c")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("a value is required"));
}

#[test]
fn missing_config_file_exits_one() {
    nmdns()
        .args(["-c", "/nonexistent/nmdns-test.toml", "--check"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("read config"));
}

#[test]
fn invalid_toml_exits_one() {
    let f = write_config("this is not = [valid toml");
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse config"));
}

#[test]
fn empty_interfaces_rejected() {
    let f = write_config("interfaces = []\n");
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("at least one interface"));
}

#[test]
fn missing_interfaces_key_rejected() {
    let f = write_config("foreground = true\n");
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn blacklist_and_whitelist_are_mutually_exclusive() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
blacklist  = ["10.0.0.0/8"]
whitelist  = ["192.168.1.0/24"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("mutually exclusive"));
}

#[test]
fn bad_subnet_in_blacklist_rejected() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
blacklist  = ["not-a-cidr"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("invalid subnet"));
}

#[test]
fn unknown_top_level_field_rejected() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
nonsense   = true
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse config"));
}

#[test]
fn unknown_service_field_rejected() {
    let f = write_config(
        r#"
interfaces = ["eth0"]

[[service]]
name      = "x"
service   = "_http._tcp.local."
port      = 80
extra_key = "boom"
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn check_succeeds_for_valid_config() {
    let f = write_config(VALID_CFG);
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .success()
        .stdout(predicate::str::contains("config OK"))
        .stdout(predicate::str::contains("1 interface"))
        .stdout(predicate::str::contains("1 service"))
        .stdout(predicate::str::contains("1 browse"));
}

#[test]
fn check_accepts_blacklist_only() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
blacklist  = ["10.0.0.0/8", "192.168.0.0/16"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .success();
}

#[test]
fn check_accepts_whitelist_only() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
whitelist  = ["192.168.50.0/24"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .success();
}

#[test]
fn check_accepts_zero_mask_meaning_any() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
blacklist  = ["0.0.0.0/0"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .success();
}

#[test]
fn check_accepts_multi_iface_and_services() {
    let f = write_config(
        r#"
interfaces = ["br-lan", "br-iot", "br-guest"]
hostname   = "router"
browse     = ["_services._dns-sd._udp.local.", "_http._tcp.local.", "_ssh._tcp.local."]

[[service]]
name    = "Admin"
service = "_http._tcp.local."
port    = 80

[[service]]
name    = "SSH"
service = "_ssh._tcp.local."
port    = 22

[[service]]
name    = "Custom"
service = "_my-thing._tcp.local."
port    = 1234
host    = "elsewhere.local."
txt     = ["a=1", "b=2"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .success()
        .stdout(predicate::str::contains("3 interface"))
        .stdout(predicate::str::contains("3 service"))
        .stdout(predicate::str::contains("3 browse"));
}

#[test]
fn example_config_validates() {
    // The shipped example must always be parseable.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/nmdns.toml");
    nmdns()
        .args(["-c"])
        .arg(&path)
        .arg("--check")
        .assert()
        .success()
        .stdout(predicate::str::contains("config OK"));
}

#[test]
fn bad_subnet_mask_too_large() {
    let f = write_config(
        r#"
interfaces = ["eth0"]
whitelist  = ["10.0.0.0/33"]
"#,
    );
    nmdns()
        .args(["-c"])
        .arg(f.path())
        .arg("--check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("mask"));
}
