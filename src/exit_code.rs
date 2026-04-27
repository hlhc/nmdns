//! Process exit codes used by the `nmdns` binary.
//!
//! `clap` exits with code 2 for command-line usage errors before `main` gets
//! control. The remaining codes are intentionally grouped so operators can
//! tell which startup phase failed from `$?`.

pub const OK: i32 = 0;
pub const USAGE: i32 = 2;

pub const CONFIG: i32 = 10;
pub const CONFIG_VALIDATION: i32 = 11;
pub const ALREADY_RUNNING: i32 = 12;
pub const DAEMONIZE: i32 = 13;
pub const RUNTIME: i32 = 14;

pub const INTERFACE_SETUP: i32 = 20;
pub const PRIVILEGE_DROP: i32 = 21;
pub const SERVICE_RECORDS: i32 = 22;
