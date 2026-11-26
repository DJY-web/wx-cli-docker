# 参与开发

本项目范围是 Docker 微信与 wx-cli 的读取集成。请使用虚构聊天数据和临时目录测试，不提交登录态、数据库、密钥或真实截图。

```sh
python3 scripts/check-compose.py
python3 -m unittest discover -s wx-cli/tests/linux -v
cd wx-cli
cargo fmt --all -- --check
cargo clippy --locked --workspace -- -D warnings
cargo test --locked --workspace
```

Linux 编译依赖 cmake、pkg-config、libclang-dev。提交前暂存并运行 `python3 scripts/check-release.py`。更新来源组件时保留原 LICENSE，并更新 sources.lock.json 与来源声明。CI 不执行真实扫码、调试捕获或消息操作。
