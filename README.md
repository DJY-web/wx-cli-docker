# wx-cli Docker

[![CI](https://github.com/DJY-web/wx-cli-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/DJY-web/wx-cli-docker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**在 Docker Linux 微信旁运行 wx-cli，给 agent 提供结构化聊天读取接口，无需关闭 macOS SIP。**

这个项目只整合两个基础组件：浏览器里的 Linux 微信桌面，以及 wx-cli 的 Linux 读取移植。包含联系人、会话、历史消息、搜索和只读 REST/SSE；不提供业务工作台、自动发送或购物流程。

## 组成与来源

| 目录 | 作用 | 原始上游 / 直接 fork |
| --- | --- | --- |
| `wx-cli/` | Rust 解密、JSON CLI、REST/SSE；Linux 进程/账号发现、经验证的登录密钥捕获 | [pandorafuture/wx-cli](https://github.com/pandorafuture/wx-cli) → [DJY-web/wx-cli](https://github.com/DJY-web/wx-cli/tree/codex/linux-port) |
| `third_party/wechat-selkies/` | Docker Linux 微信桌面，通过浏览器扫码登录 | [nickrunning/wechat-selkies](https://github.com/nickrunning/wechat-selkies) → [DJY-web/wechat-selkies](https://github.com/DJY-web/wechat-selkies) |
| `compose.yaml`、`scripts/`、`examples/` | 把两者放在同一 Docker 项目，供人和 agent 使用 | 本项目的集成层 |

源码快照直接纳入仓库，一次 clone 即可取得；原版权、许可证和固定提交见 [来源声明](THIRD_PARTY_NOTICES.md) 与 [sources.lock.json](sources.lock.json)。

## 为什么不需要关闭 SIP

微信运行在 Docker 的 Linux 环境中。取密钥时，临时辅助容器只附加同一 Docker 微信的 Linux 进程；后续查询通过只读数据库挂载完成。这个流程不读取 Mac 微信，也不修改 macOS SIP。

这并不等于完全没有权限要求：首次取密钥需要你明确同意临时容器调试、短暂停顿和私有密钥保存，并手动重新登录。正常读取服务没有 SYS_PTRACE 权限。

## 已验证的范围

- 目标：Apple Silicon 上的 Docker Linux ARM64，微信 4.1.13.29。
- 登录密钥捕获、数据库 HMAC 校验、真实联系人/会话/历史消息、带 token API 和 SSE 连接已验证。
- AMD64 可构建读取核心；当前 GDB 登录定位器仅支持 ARM64，不能宣称 AMD64 自动取密钥可用。
- 不同微信版本需重新验证。单纯内存扫描在上述版本没有取得有效密钥。
- SSE 连接测试与历史消息查询不等同于所有新消息场景都已完成验收。

## 开始使用

需要 Docker Desktop/Engine、Docker Compose 和 Python 3.11+（初始化、示例脚本使用标准库）。Mac 不需要安装原生微信或改变 SIP。

### 1. 启动容器微信

```sh
git clone https://github.com/DJY-web/wx-cli-docker.git
cd wx-cli-docker
sh scripts/wx-cli.sh start
```

首次自动生成权限为 0600 的 `.env`。本机打开该文件查看 WECHAT_USER / WECHAT_PASSWORD，登录 <http://127.0.0.1:3000> 的桌面，再用手机扫码登录容器微信。不要公开 `.env`。

桌面太小时，在 Selkies 侧边栏关闭 HiDPI，调整为 1280×720 并最大化微信。若本机端口 3000/3001 已被其他服务占用，先调整端口配置，不要删除已有微信数据卷。

### 2. 构建 wx-cli

```sh
sh scripts/wx-cli.sh build
```

构建读取镜像与独立捕获镜像。默认微信桌面使用固定摘要的上游镜像；wx-cli 从本仓库源码构建。

### 3. 经同意后捕获数据库密钥

```sh
sh scripts/wx-cli.sh capture
```

执行前须同意临时 GDB 附加和密钥保存。看到 `Debugger ready` 后，在**容器微信**退出账号，再扫码登录同一账号。不要关闭 Docker 或容器。成功后自动解除调试，密钥通过 HMAC 验证才写入私有 `wx-cli-state` 卷，日志不打印密钥。

默认最多等 600 秒；超时解除调试，不自动重启微信。首次捕获后普通使用不需要重复附加调试器。换账号、重建数据或升级后若校验失败，再检查是否需要重新捕获。

### 4. 查询与给 agent 使用

```sh
sh scripts/wx-cli.sh run contacts --limit 10 --format json --no-server
sh scripts/wx-cli.sh run sessions --limit 10 --format json --no-server
sh scripts/wx-cli.sh run query '联系人标识' --limit 20 --format json --no-server
sh scripts/wx-cli.sh run search '关键词' --format json --no-server
```

启动 REST/SSE：

```sh
sh scripts/wx-cli.sh server
python3 examples/api.py /api/v1/health
python3 examples/api.py '/api/v1/sessions?limit=10'
```

示例在本机内存中读取 token，只输出请求结果，不打印 token。将 CLI JSON 或 REST 结果交给你自己的 agent 即可；本项目没有内置外部 LLM 账号或服务。

| 地址 | 用途 |
| --- | --- |
| `127.0.0.1:3000` / `3001` | 微信远程桌面 HTTP / HTTPS |
| `127.0.0.1:9100/api/v1/health` | 读取服务健康检查 |
| `/api/v1/contacts`、`/sessions`、`/messages`、`/search` | REST 查询 |
| `/api/v1/events` | SSE 流，需使用流式客户端而不是 JSON 示例 |

API 都要求 Bearer token；未认证返回 401。token 位于当前项目私有卷 `/state/config/wx-cli/api-token`。所有发布端口都只绑定本机。

## 数据与启停

```sh
sh scripts/wx-cli.sh stop                 # 只停止读取 API
sh scripts/docker.sh compose --profile cli down  # 停止当前项目容器，保留卷
```

- `wechat-config`：微信登录和数据库。
- `wx-cli-state`：密钥、token、读取缓存与状态。
- 本仓库不包含这些运行数据。保留数据时不要执行 down -v。
- 默认项目名 `wx-cli-docker`，不会自动接管其他项目的容器或迁移旧卷。

## 可选：从源码构建微信桌面

```sh
sh scripts/docker.sh compose -f compose.yaml -f compose.wechat-build.yaml build wechat
sh scripts/docker.sh compose -f compose.yaml -f compose.wechat-build.yaml up -d wechat
```

使用本仓库保留的 wechat-selkies 快照，关闭 QQ 安装，并传入记录的微信安装包 SHA256。上游安装包改变时应审查升级；不要跳过校验。基础镜像仍由上游提供，源码快照和默认镜像摘要分别记录，不声称两者一定来自同一次构建。

## 开发与开源

参见 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[CITATION.cff](CITATION.cff)。本项目集成代码采用 [MIT](LICENSE)，两个来源目录完整保留原许可证与版权；基础镜像、微信客户端和依赖适用各自条款，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。
