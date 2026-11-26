# 安全报告

请勿在公开 Issue 中上传聊天、密钥、token、Cookie、登录二维码或真实截图。使用 [GitHub 私密漏洞报告](https://github.com/DJY-web/wx-cli-docker/security/advisories/new) 提供脱敏的复现步骤。

维护分支为 main。所有发布端口默认只绑定本机；读取 API 要求 token。常规 wx-cli 容器无调试权限，只有使用者同意后手动启动的临时捕获容器可以附加当前 Docker 微信。

本项目不需要关闭宿主 macOS SIP，不访问 Mac 微信数据，不向容器挂载 Docker socket。运行数据与备份应留在使用者自己的私有存储。
