# wx-cli Linux / Docker 接入

本目录是 wx-cli 的 Linux 移植源码。统一使用方式见 [项目根 README](../README.md)。

- 根目录运行 `sh scripts/wx-cli.sh start` 启动 Linux 微信桌面。
- `sh scripts/wx-cli.sh build` 从本仓库源码构建读取和临时捕获镜像。
- 首次取密钥需同意临时调试，执行 `sh scripts/wx-cli.sh capture`，等 Debugger ready 后手动退出并重新扫码登录容器微信。
- `sh scripts/wx-cli.sh server` 启动需要 token 的只读 REST/SSE。
- `sh scripts/wx-cli.sh run sessions --format json --no-server` 查询会话。

Linux 的密钥、缓存和状态遵循 XDG 目录；容器内分别放在 /state/config、/state/cache、/state/state。微信数据库根目录为 /config/xwechat_files，只读挂载；不访问宿主 Mac 微信。

开发验证环境为 Linux ARM64 微信 4.1.13.29。原始密钥必须通过数据库 HMAC 校验后才保存，Linux 密钥库以 0600 写入。静态内存扫描在该版本未取得有效密钥；ARM64 登录时 GDB 捕获已验证。AMD64 可以编译读取核心，但当前 ARM64 定位器不提供 AMD64 登录捕获支持。

常规服务无需调试权限。只有显式捕获容器临时附加当前 Docker 微信，需要 SYS_PTRACE 等容器权限；它不重启微信，不关闭 Mac SIP，也不读取 Mac 进程。不要运行会显示原始密钥的 key list 并把输出贴到公开日志。

源码来源和本地改动见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) 与 [sources.lock.json](../sources.lock.json)。下层上游 README / SKILL 中的原生 macOS SIP、LLDB 步骤不适用于本 Docker 集成。
