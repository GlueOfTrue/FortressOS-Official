//! Host-side BUILD tooling. No physical block-device IO is implemented.
mod image;
mod manifest;
mod qemu;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const TARGET: &str = "x86_64-unknown-uefi";
pub(crate) const SIGNATURE_OK: &str = "FORTRESSOS_G0_DIAG_V1 BOOT_OK";
pub(crate) const SIGNATURE_FAIL: &str = "FORTRESSOS_G0_DIAG_V1 BOOT_FAIL";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Debug,
    Release,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cpu {
    Generic,
    V3,
}
#[derive(Clone, Debug)]
struct Config {
    profile: Profile,
    cpu: Cpu,
    timeout: Duration,
    gdb: bool,
    fault_probe: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            profile: Profile::Debug,
            cpu: Cpu::Generic,
            timeout: Duration::from_secs(45),
            gdb: false,
            fault_probe: false,
        }
    }
}
impl Config {
    fn profile_name(&self) -> &'static str {
        match self.profile {
            Profile::Debug => "debug",
            Profile::Release => "release",
        }
    }
    fn cpu_name(&self) -> &'static str {
        match self.cpu {
            Cpu::Generic => "generic",
            Cpu::V3 => "x86-64-v3",
        }
    }
    fn cpu_flags(&self) -> &'static str {
        match self.cpu {
            Cpu::Generic => "-Ctarget-cpu=x86-64",
            Cpu::V3 => "-Ctarget-cpu=x86-64-v3",
        }
    }
    fn out_dir(&self) -> PathBuf {
        let variant = if self.fault_probe {
            "fault-probe"
        } else {
            "normal"
        };
        target_root()
            .join("fortress-artifacts")
            .join(self.profile_name())
            .join(self.cpu_name())
            .join(variant)
    }
}
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn target_root() -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(p) => {
            let p = PathBuf::from(p);
            if p.is_absolute() {
                p
            } else {
                root().join(p)
            }
        }
        None => root().join("target"),
    }
}
fn cargo() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}
fn run_cargo(args: &[&str], config: Option<&Config>) -> Result<(), String> {
    let mut cmd = Command::new(cargo());
    cmd.current_dir(root()).args(args);
    if let Some(config) = config {
        // Don't leak target flags to the host xtask itself.
        cmd.env("CARGO_ENCODED_RUSTFLAGS", config.cpu_flags());
        cmd.env_remove("RUSTFLAGS");
    }
    let status = cmd.status().map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err(format!("cargo {args:?} failed with {status}"));
    }
    Ok(())
}
fn build(config: &Config) -> Result<PathBuf, String> {
    let mut args = vec![
        "build",
        "--locked",
        "-p",
        "fortress-diag",
        "--target",
        TARGET,
    ];
    if config.profile == Profile::Release {
        args.push("--release");
    }
    if config.fault_probe {
        args.extend(["--features", "fault-probe"]);
    }
    run_cargo(&args, Some(config))?;
    let compiled = target_root()
        .join(TARGET)
        .join(config.profile_name())
        .join("fortress-diag.efi");
    let data = fs::read(&compiled)
        .map_err(|e| format!("cannot read compiled EFI {}: {e}", compiled.display()))?;
    check_pe(&data)?;
    let boot = config.out_dir().join("BOOTX64.EFI");
    fs::create_dir_all(config.out_dir()).map_err(|e| e.to_string())?;
    fs::write(&boot, data).map_err(|e| format!("cannot write {}: {e}", boot.display()))?;
    println!("EFI artifact: {}", boot.display());
    Ok(boot)
}
fn check_pe(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
        return Err("invalid PE: missing MZ DOS header".into());
    }
    let off = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    if off > bytes.len().saturating_sub(96) || &bytes[off..off + 4] != b"PE\0\0" {
        return Err("invalid PE: PE signature/offset".into());
    }
    if u16::from_le_bytes(bytes[off + 4..off + 6].try_into().unwrap()) != 0x8664 {
        return Err("invalid PE: not AMD64 (0x8664)".into());
    }
    let optional = off + 24;
    if u16::from_le_bytes(bytes[optional..optional + 2].try_into().unwrap()) != 0x20b {
        return Err("invalid PE: not PE32+".into());
    }
    if u16::from_le_bytes(bytes[optional + 68..optional + 70].try_into().unwrap()) != 10 {
        return Err("invalid PE: subsystem is not EFI application (10)".into());
    }
    Ok(())
}
fn create_image(config: &Config) -> Result<PathBuf, String> {
    let efi = build(config)?;
    let dest = config.out_dir().join("esp.img");
    image::write_esp(&efi, &dest)?;
    image::verify_esp(&dest)?;
    manifest::write(config, &efi, &dest)?;
    println!("QEMU removable FAT32 image: {}", dest.display());
    Ok(dest)
}
fn usage() -> &'static str {
    "Usage: cargo xtask <build|image|qemu|test> [--release] [--cpu generic|v3] [--timeout SECONDS] [--gdb] [--fault-probe]\n     Defaults: debug, generic, 45s, TCG. --gdb listens on 127.0.0.1:1234 and pauses the guest.\n     --fault-probe is a CI negative fixture; it must NEVER pass the success gate."
}
fn cli() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let action = args.next().ok_or_else(|| usage().to_string())?;
    let mut config = Config::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--release" => config.profile = Profile::Release,
            "--cpu" => {
                config.cpu = match args.next().as_deref() {
                    Some("generic") => Cpu::Generic,
                    Some("v3") => Cpu::V3,
                    _ => return Err("expected --cpu generic|v3".into()),
                };
            }
            "--timeout" => {
                let value = args.next().ok_or("missing --timeout value")?;
                let seconds: u64 = value
                    .parse()
                    .map_err(|_| "timeout must be seconds as integer")?;
                if !(1..=3600).contains(&seconds) {
                    return Err("timeout must be 1..=3600 seconds".into());
                }
                config.timeout = Duration::from_secs(seconds);
            }
            "--gdb" => config.gdb = true,
            "--fault-probe" => config.fault_probe = true,
            _ => return Err(format!("unknown option {arg}\n{}", usage())),
        }
    }
    match action.as_str() {
        "build" => {
            build(&config)?;
        }
        "image" => {
            create_image(&config)?;
        }
        "qemu" => {
            let disk = create_image(&config)?;
            qemu::boot(&config, &disk)?;
        }
        "test" => {
            if config.fault_probe || config.gdb {
                return Err("test does not accept --fault-probe or --gdb".into());
            }
            run_cargo(&["test", "--locked", "-p", "xtask"], None)?;
            let disk = create_image(&config)?;
            qemu::boot(&config, &disk)?;
            let mut negative = config.clone();
            negative.fault_probe = true;
            let disk = create_image(&negative)?;
            let result = qemu::boot(&negative, &disk);
            if result.is_ok() {
                return Err("negative fixture incorrectly accepted".into());
            }
            let log = fs::read_to_string(negative.out_dir().join("serial.log"))
                .map_err(|e| format!("negative serial log missing: {e}"))?;
            if !log.contains(SIGNATURE_FAIL) {
                return Err(format!("negative fixture did not execute: {result:?}"));
            }
            println!("PASS: negative boot rejected with expected diagnostic signature");
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}
fn main() {
    if let Err(err) = cli() {
        eprintln!("xtask ERROR: {err}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pe_rejects_empty_and_wrong_machine() {
        assert!(check_pe(&[]).is_err());
        let mut b = vec![0; 512];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        b[0x98 + 68..0x98 + 70].copy_from_slice(&10u16.to_le_bytes());
        assert!(check_pe(&b).is_ok());
        b[0x84] = 0x4c;
        assert!(check_pe(&b).is_err());
    }
    #[test]
    fn cpu_policy_never_uses_native() {
        assert_eq!(Config::default().cpu_flags(), "-Ctarget-cpu=x86-64");
        let config = Config {
            cpu: Cpu::V3,
            ..Config::default()
        };
        assert_eq!(config.cpu_flags(), "-Ctarget-cpu=x86-64-v3");
    }
}
