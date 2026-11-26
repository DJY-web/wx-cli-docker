# 项目约定

- 项目仅整合 Docker Linux 微信和 wx-cli 读取工具。使用根 README 与 scripts/wx-cli.sh。
- 不关闭 macOS SIP，不访问宿主 Mac 微信数据，不把 Docker socket 挂入容器。
- 测试使用临时目录与虚构消息，不操作真实账号。
- 临时 GDB 捕获需使用者同意并手动重新登录，不能在常规服务启动时自动附加。
- 保护密钥、token、登录态和聊天内容；不把运行数据或截图提交 Git。
- 修改来源组件时保留版权，更新来源锁文件；第三方 AGENTS.md 仅适用于其目录。
