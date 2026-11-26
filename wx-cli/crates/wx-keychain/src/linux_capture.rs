//! Explicit debugger capture for Linux ARM64. Never automatically restarts WeChat.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use crate::{AccountDirInfo, KeychainError};

struct PrivateCaptureDir(PathBuf);

impl Drop for PrivateCaptureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn capture(timeout_secs: u64) -> Result<([u8; 32], AccountDirInfo, String), KeychainError> {
    if !(1..=3600).contains(&timeout_secs) {
        return Err(KeychainError::Other(
            "capture timeout must be 1..3600 seconds".into(),
        ));
    }
    let (pid, version) = crate::find_wechat_pid()?;
    let accounts = crate::find_account_dirs()?;
    if accounts.is_empty() {
        return Err(KeychainError::AccountNotDetected);
    }
    let config = crate::config_dir()?;
    wx_paths::AppPaths::ensure_dir(&config)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| KeychainError::Other(e.to_string()))?
        .as_nanos();
    let directory = config.join(format!(".capture-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let guard = PrivateCaptureDir(directory);
    std::fs::set_permissions(&guard.0, std::fs::Permissions::from_mode(0o700))?;
    let script = guard.0.join("capture.py");
    let output = guard.0.join("validated-key");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&script)?;
    file.write_all(include_bytes!("linux_capture.py"))?;
    drop(file);

    let mut command = Command::new("python3");
    command
        .arg(&script)
        .args([
            "--pid",
            &pid.to_string(),
            "--timeout",
            &timeout_secs.to_string(),
            "--output",
        ])
        .arg(&output);
    for account in &accounts {
        command.arg("--db").arg(&account.message_db_path);
    }
    eprintln!("Linux ARM64 debugger capture requested. This briefly pauses WeChat at key setup.");
    eprintln!("No automatic restart/logout. Wait for 'Debugger ready', then manually sign out and sign in.");
    let status = command.status().map_err(|e| {
        KeychainError::Other(format!(
            "cannot run Linux capture helper (requires python3 and gdb): {e}"
        ))
    })?;
    if !status.success() {
        return Err(KeychainError::Other(
            "Linux debugger capture did not obtain a validated key; see helper message above"
                .into(),
        ));
    }
    let value = std::fs::read_to_string(&output)?;
    let bytes = hex::decode(value.trim()).map_err(|_| KeychainError::KeySaltMismatch)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeychainError::KeySaltMismatch)?;
    // Never trust helper output alone: validate again in the Rust crypto core.
    for account in accounts {
        let mut page = vec![0; wx_decrypt::MACOS_4_1_7_31.page_size];
        if File::open(&account.message_db_path)
            .and_then(|mut f| f.read_exact(&mut page))
            .is_ok()
            && wx_decrypt::validate_key(&page, &key, &wx_decrypt::MACOS_4_1_7_31).is_some()
        {
            return Ok((key, account, version));
        }
    }
    Err(KeychainError::KeySaltMismatch)
}
