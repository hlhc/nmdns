//! Daemonization, pidfile, setuid \u2014 ported from the v0.1 implementation.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::process;

use nix::sys::signal::{kill, Signal};
use nix::sys::stat::{umask, Mode};
use nix::unistd::{
    chdir, dup2_stderr, dup2_stdin, dup2_stdout, fork, setgid, setsid, setuid, ForkResult, Gid,
    Pid, Uid, User,
};

pub fn read_pid(path: &str) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn already_running(path: &str) -> Option<i32> {
    let pid = read_pid(path)?;
    match kill(Pid::from_raw(pid), None) {
        Ok(_) => Some(pid),
        Err(_) => None,
    }
}

pub fn write_pidfile(path: &str) -> io::Result<()> {
    let mut f = File::create(path)?;
    write!(f, "{}", process::id())?;
    Ok(())
}

pub fn switch_user(name: &str) -> io::Result<()> {
    let user = User::from_name(name)
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no such user: {name}")))?;
    setgid(Gid::from_raw(user.gid.as_raw())).map_err(io::Error::from)?;
    setuid(Uid::from_raw(user.uid.as_raw())).map_err(io::Error::from)?;
    Ok(())
}

fn redirect_stdio_to_devnull() -> io::Result<()> {
    let dn = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    dup2_stdin(&dn).map_err(io::Error::from)?;
    dup2_stdout(&dn).map_err(io::Error::from)?;
    dup2_stderr(&dn).map_err(io::Error::from)?;
    Ok(())
}

/// Classic fork/setsid daemonize. Call **before** the tokio runtime starts;
/// the child returns and proceeds to runtime setup. The pidfile is written
/// *before* stdio is redirected so a failure is visible to the operator.
pub fn daemonize(pid_file: &str) -> io::Result<()> {
    match unsafe { fork() }.map_err(io::Error::from)? {
        ForkResult::Parent { .. } => process::exit(crate::exit_code::OK),
        ForkResult::Child => {}
    }

    unsafe {
        let _ = nix::sys::signal::signal(Signal::SIGHUP, nix::sys::signal::SigHandler::SigIgn);
        let _ = nix::sys::signal::signal(Signal::SIGCHLD, nix::sys::signal::SigHandler::SigIgn);
    }

    setsid().map_err(io::Error::from)?;
    umask(Mode::from_bits_truncate(0o027));
    chdir("/").map_err(io::Error::from)?;

    // Write the pidfile before silencing stderr so an EACCES/EROFS failure
    // is visible. Treat it as fatal: a missing pidfile breaks
    // `already_running` on the next start.
    write_pidfile(pid_file)?;

    redirect_stdio_to_devnull()?;
    Ok(())
}
