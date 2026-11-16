use crate::{Config, SIGNATURE_OK};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn locate_firmware(name: &str, candidates: &[&str]) -> Result<PathBuf, String> {
    if let Some(value) = env::var_os(name) {
        let p = PathBuf::from(value);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!(
            "{name} points to missing firmware: {}",
            p.display()
        ));
    }
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| {
            format!("missing OVMF firmware: set {name} to a file path (see docs/BUILD.md)")
        })
}

fn ovmf() -> Result<(PathBuf, PathBuf), String> {
    let code = locate_firmware(
        "FORTRESS_OVMF_CODE",
        &[
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
            "/usr/local/share/qemu/edk2-x86_64-code.fd",
        ],
    )?;
    let vars = locate_firmware(
        "FORTRESS_OVMF_VARS",
        &[
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
            "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
            "/usr/local/share/qemu/edk2-i386-vars.fd",
        ],
    )?;
    Ok((code, vars))
}
pub fn boot(config: &Config, disk: &Path) -> Result<(), String> {
    let (code, vars_source) = ovmf()?;
    let vars = config.out_dir().join("OVMF_VARS.fd");
    fs::copy(&vars_source, &vars).map_err(|e| format!("cannot copy OVMF VARS: {e}"))?;
    let log = config.out_dir().join("serial.log");
    fs::write(&log, "").map_err(|e| format!("cannot initialize serial log: {e}"))?;
    let qemu = env::var_os("FORTRESS_QEMU").unwrap_or_else(|| "qemu-system-x86_64".into());
    let mut cmd = Command::new(&qemu);
    cmd.args([
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "qemu64",
        "-m",
        "256M",
        "-nodefaults",
        "-display",
        "none",
        "-monitor",
        "none",
        "-no-reboot",
        "-serial",
        &format!("file:{}", log.display()),
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-drive",
        &format!("if=pflash,format=raw,readonly=on,file={}", code.display()),
        "-drive",
        &format!("if=pflash,format=raw,file={}", vars.display()),
        "-device",
        "qemu-xhci",
        "-drive",
        &format!(
            "if=none,id=esp,format=raw,readonly=on,file={}",
            disk.display()
        ),
        "-device",
        "usb-storage,drive=esp,removable=on",
        "-boot",
        "order=d",
    ]);
    if config.gdb {
        cmd.args(["-S", "-gdb", "tcp:127.0.0.1:1234"]);
    }
    println!(
        "QEMU mode=TCG profile={} cpu={} timeout={:?} serial={}",
        config.profile_name(),
        config.cpu_name(),
        config.timeout,
        log.display()
    );
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("could not launch {:?}: {e}", qemu))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            let serial = fs::read_to_string(&log).unwrap_or_default();
            println!("--- guest serial ---\n{serial}--- end serial ---");
            // QEMU isa-debug-exit: ((guest code << 1) | 1). 0x10 => 33.
            if status.code() == Some(33) && serial.contains(SIGNATURE_OK) && !config.fault_probe {
                return Ok(());
            }
            return Err(format!("QEMU boot failed: status={status}, success_signature={}, fault_probe={}, serial={}",
                serial.contains(SIGNATURE_OK), config.fault_probe, log.display()));
        }
        if start.elapsed() >= config.timeout {
            child
                .kill()
                .map_err(|e| format!("QEMU timeout; failed to terminate guest: {e}"))?;
            let _ = child.wait();
            return Err(format!(
                "QEMU timeout after {:?}; serial log={}",
                config.timeout,
                log.display()
            ));
        }
        thread::sleep(Duration::from_millis(40));
    }
}
