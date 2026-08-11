# OpenCLI Profile 接入验证（todo 17）

## 验证方法（源码/文档核查，2026-08-11）

- `opencli --help` → `--profile <name>` 标注为 "Chrome profile/context alias for
  Browser"；`opencli profile list` 走 **Browser Bridge 扩展**（本机有 1 个已连接
  profile `9es4h3qa`）。
- `opencli profile` 子命令仅 `list|rename|use`，管理的是 Browser Bridge 的 context
  alias，**不是** 任意 user-data-dir 路径。
- 结论：opencli 的 `--profile` 不能直接消费 wrapper 生成的 user-data-dir 目录 +
  `--proxy-server` flag（两者是不同机制：Browser Bridge context alias vs 原生
  Chrome 启动参数）。

## Fallback（按 plan todo 17 采用）

- wrapper 生成的 profile（`~/.local/share/reach-guard/profiles/<platform>/<account>/`，
  0700）是标准 Chrome user-data-dir，含 `profile.flags`：
  `--proxy-server=<url>` + `--webrtc-ip-handling-policy=disable_non_proxied_udp`。
- 使用方式：以该 user-data-dir 启动 Chrome / 在 opencli 的 Browser Bridge 中复用
  该 profile 的登录态 + 手动注入 flags；opencli 流量经 Chrome 走 profile 代理。
- **无法注入 / 无代理 → 该平台 fail-closed exit 3**（小红书/微博/抖音/IG/FB 全强制）。

## egress 验证

- 无代理配置时：跳过网络验证，`profile` 命令明确提示 "egress verification SKIPPED:
  no proxy configured"。binding 平台的 run 在运行时 fail-closed exit 3（预期）。
- 有代理时：`reach-guard profile --platform <p> --account <a> --proxy-url <u>`
  会经代理解析出口 IP 并打印。
