# 来源、版权与改动

| 部分 | 原始上游 | 直接来源 | 固定提交 / 许可证 |
| --- | --- | --- | --- |
| `wx-cli/` | [pandorafuture/wx-cli](https://github.com/pandorafuture/wx-cli) | [DJY-web/wx-cli 的 Linux 分支](https://github.com/DJY-web/wx-cli/tree/codex/linux-port) | `d1ab54792999fba21087f35b1c11c3b4f1c00dca`；上游基点 `2abe708f55bfe135539a385df856fdc58f97fc74`；MIT，Copyright 2026 pandorafuture；[原 LICENSE](wx-cli/LICENSE) |
| `third_party/wechat-selkies/` | [nickrunning/wechat-selkies](https://github.com/nickrunning/wechat-selkies) | [DJY-web/wechat-selkies](https://github.com/DJY-web/wechat-selkies) | `f3eeb94860f060b1909f0151bc0fa175c13a40c1`；MIT，Copyright 2025 Nick007；[原 LICENSE](third_party/wechat-selkies/LICENSE) |

固定来源与本地差异见 sources.lock.json。来源目录以源码快照形式纳入，不包含嵌套 Git 历史或任何登录数据。

## 修改范围

- Linux wx-cli 移植保留上游 Rust 查询核心，增加 Linux 账号/进程发现、只读内存读取、ARM64 登录捕获、数据库 HMAC 校验、私有密钥写入与前台 HTTP 服务。
- 本项目整合 Compose、启动/查询脚本和 agent API 示例；补充通用 Docker 文档、镜像元数据和许可证打包；保留兼容新版 Clippy 的定长分块迭代及隔离 HOME/XDG/sudo 的测试修复。原独立部署脚本改为通用入口转发，移除部署专用的文档与默认容器名。
- wechat-selkies 的 Git 跟踪文件保持与上述固定提交一致，没有改写桌面脚本。可选源码构建通过根目录覆盖配置完成。

## 运行时与依赖

默认桌面镜像由 ghcr.io/nickrunning/wechat-selkies 上游发布。其摘要与源码提交分别记录，不把上游镜像声称为本项目自行构建。

wechat-selkies 源码 LICENSE 为 MIT；其 Dockerfile 保留的 OCI license 标签为 GPL-3.0-only。基础镜像及系统依赖有各自许可证，不把整个运行环境统一表述为 MIT。微信/QQ 客户端由 Tencent 提供，客户端与商标不在本项目 MIT 授权范围；仓库不包含安装包。

Rust 依赖锁定于 wx-cli/Cargo.lock，各自保留原授权。ARM64 捕获研究参考 [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool)、[Tencent/WCDB](https://github.com/Tencent/wcdb) 及 SQLCipher；未将该参考项目源码纳入仓库。

本项目与 Tencent 或原项目维护者没有官方合作或背书关系。请保留两个来源目录的 LICENSE 与原版权声明。
