use std::path::Path;
use std::process::Command;

/// Keep fixture subprocesses independent of the developer/runner account.
pub fn isolated_command(binary: &str, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_STATE_HOME", home.join(".local/state"));
    for name in [
        "SUDO_USER",
        "SUDO_UID",
        "SUDO_GID",
        "WECHAT_CLI_DATA_DIR",
        "WECHAT_CLI_ACCOUNT",
        "WECHAT_CLI_KEY",
        "WX_CLI_WECHAT_DATA_ROOT",
        "WECHAT_CLI_SERVER_URL",
        "WECHAT_CLI_SERVER_TOKEN",
    ] {
        command.env_remove(name);
    }
    command
}
