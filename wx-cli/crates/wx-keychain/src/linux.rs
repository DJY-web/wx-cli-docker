//! Linux process and database discovery. No restart, ptrace attach, or memory writes.
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::mach_vm::{MemRegion, MemoryReader};
use crate::KeychainError;

pub fn data_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots = vec![
        home.join("xwechat_files"),
        home.join("Documents/xwechat_files"),
        home.join(".local/share/WeChat/xwechat_files"),
        PathBuf::from("/config/xwechat_files"),
    ];
    roots.sort();
    roots.dedup();
    roots
}

fn is_main_wechat_process(proc_root: &Path, pid: u32) -> bool {
    let name =
        std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm")).unwrap_or_default();
    matches!(name.trim(), "wechat" | "WeChat" | "weixin")
}

fn find_in_proc(proc_root: &Path, explicit_pid: Option<u32>) -> Result<u32, KeychainError> {
    if let Some(pid) = explicit_pid {
        return if is_main_wechat_process(proc_root, pid) {
            Ok(pid)
        } else {
            Err(KeychainError::Other(
                "WX_CLI_WECHAT_PID is not a running main WeChat process".into(),
            ))
        };
    }
    let mut pids: Vec<u32> = std::fs::read_dir(proc_root)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| is_main_wechat_process(proc_root, *pid))
        .collect();
    pids.sort_unstable();
    match pids.as_slice() {
        [pid] => Ok(*pid),
        [] => Err(KeychainError::WeChatNotRunning),
        _ => Err(KeychainError::Other(
            "multiple main WeChat processes found; set WX_CLI_WECHAT_PID explicitly".into(),
        )),
    }
}

pub fn find_wechat_pid() -> Result<u32, KeychainError> {
    let explicit = std::env::var("WX_CLI_WECHAT_PID")
        .ok()
        .map(|s| {
            s.parse::<u32>().map_err(|_| {
                KeychainError::Other("WX_CLI_WECHAT_PID must be a positive integer".into())
            })
        })
        .transpose()?;
    find_in_proc(Path::new("/proc"), explicit)
}

fn package_version(status: &str) -> Option<String> {
    status.split("\n\n").find_map(|paragraph| {
        let package = paragraph
            .lines()
            .find_map(|l| l.strip_prefix("Package: "))?;
        if !matches!(package, "wechat" | "weixin") {
            return None;
        }
        paragraph.lines().find_map(|l| {
            l.strip_prefix("Version: ")
                .map(str::trim)
                .map(str::to_owned)
        })
    })
}

pub fn wechat_version() -> Result<String, KeychainError> {
    if let Ok(value) = std::env::var("WX_CLI_WECHAT_VERSION") {
        return Ok(value);
    }
    // Works both inside the desktop and in a PID-namespace-sharing scan sidecar.
    let pid = find_wechat_pid()?;
    for path in [
        PathBuf::from(format!("/proc/{pid}/root/var/lib/dpkg/status")),
        PathBuf::from("/var/lib/dpkg/status"),
    ] {
        if let Ok(status) = std::fs::read_to_string(path) {
            if let Some(version) = package_version(&status) {
                return Ok(version);
            }
        }
    }
    Err(KeychainError::Other("cannot determine Linux WeChat version; set WX_CLI_WECHAT_VERSION to the installed package version".into()))
}

/// Open read-only, never ptrace-attach or stop WeChat. Kernel access checks apply.
pub struct ProcMemReader {
    pid: u32,
    mem: File,
}

impl ProcMemReader {
    pub fn attach(pid: u32) -> Result<Self, KeychainError> {
        if !is_main_wechat_process(Path::new("/proc"), pid) {
            return Err(KeychainError::WeChatNotRunning);
        }
        let mem = File::open(format!("/proc/{pid}/mem")).map_err(|err| {
            KeychainError::Other(format!("cannot read WeChat /proc/{pid}/mem: {err}; use the scoped scan sidecar with SYS_PTRACE in WeChat's PID namespace, or supply existing keys; no host ptrace sysctl change is required"))
        })?;
        Ok(Self { pid, mem })
    }
}

fn parse_rw_maps(maps: &str) -> Vec<MemRegion> {
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let perms = fields.next()?.as_bytes();
            if perms.len() < 2 || perms[0] != b'r' || perms[1] != b'w' {
                return None;
            }
            let (start, end) = address.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            (end > start).then_some(MemRegion { start, end })
        })
        .collect()
}

impl MemoryReader for ProcMemReader {
    fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        Ok(parse_rw_maps(&maps))
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
        let mut data = vec![0; len];
        let n = self.mem.read_at(&mut data, addr)?;
        if n == 0 {
            return Err(KeychainError::Other(
                "WeChat memory mapping disappeared".into(),
            ));
        }
        data.truncate(n);
        Ok(data)
    }
}

pub fn preflight_checks() -> Vec<crate::PreflightCheck> {
    let access = find_wechat_pid().and_then(ProcMemReader::attach);
    vec![crate::PreflightCheck {
        name: "Linux WeChat memory",
        passed: access.is_ok(),
        detail: match access {
            Ok(_) => "read-only /proc access available; WeChat is not stopped".into(),
            Err(e) => e.to_string(),
        },
        fix_cmd: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_include_only_valid_read_write_ranges() {
        let maps = "1000-2000 rw-p 0 0:0 0 [heap]\n2000-3000 r-xp 0 0:0 0 /opt/wechat/wechat\n3000-3000 rw-p 0 0:0 0\nbad rw-p\n4000-5000 rw-s 0 0:0 0 /dev/shm/example\n";
        let regions = parse_rw_maps(maps);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].start, 0x1000);
        assert_eq!(regions[1].end, 0x5000);
    }

    #[test]
    fn process_discovery_ignores_helpers_and_rejects_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        for (pid, name) in [(21, "wechat"), (22, "WeChatAppEx")] {
            std::fs::create_dir(dir.path().join(pid.to_string())).unwrap();
            std::fs::write(dir.path().join(format!("{pid}/comm")), name).unwrap();
        }
        assert_eq!(find_in_proc(dir.path(), None).unwrap(), 21);
        assert!(find_in_proc(dir.path(), Some(22)).is_err());
        std::fs::create_dir(dir.path().join("23")).unwrap();
        std::fs::write(dir.path().join("23/comm"), "wechat\n").unwrap();
        assert!(find_in_proc(dir.path(), None).is_err());
        assert_eq!(find_in_proc(dir.path(), Some(23)).unwrap(), 23);
    }

    #[test]
    fn package_version_is_bound_to_wechat_package() {
        let status = "Package: other\nVersion: 99\n\nPackage: wechat\nVersion: 4.1.13.29\n";
        assert_eq!(package_version(status).as_deref(), Some("4.1.13.29"));
        assert_eq!(package_version("Package: other\nVersion: 99\n"), None);
    }

    #[test]
    fn selkies_root_is_present_without_duplicate_home() {
        let roots = data_roots(Path::new("/config"));
        assert_eq!(
            roots
                .iter()
                .filter(|p| **p == Path::new("/config/xwechat_files"))
                .count(),
            1
        );
    }
}
