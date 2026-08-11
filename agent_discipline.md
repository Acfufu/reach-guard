# Agent Discipline — reach-guard (STRICT)

This fragment binds every agent in this workspace to the reach-guard enforced
entry point. It ships as part of the reach-guard project and should be copied
into AGENTS.md / CLAUDE.md of any repo whose agent drives platform traffic.

## 非目标 (Must-NOT)

- 直连任一被包装二进制（`agent-reach|twitter|bili|opencli|gh|yt-dlp|mcporter|curl`）——一律经过 reach-guard。**gh 例外**（GitHub 豁免路径，仅日志）。
- 修改 agent-reach / 上游源码、配置语义、存储格式。
- 新增凭据副本；凭据只经 env 注入（OpenCLI 专用 Chrome profile 0700 是唯一例外载体）。
- 使用 `--relaxed` / 任何静默降级 strict 模式的参数（不存在）。
- 对表外平台 / 未知二进制放行（fail-closed exit 6 / exit 8）。

## 调用规则

```
~/.local/bin/<bin> ...        # shim 自动转发 reach-guard run
reach-guard run <bin> <args>  # 显式形式
```

1. 只读默认；写操作（publish/post/follow/send/favorite/comment/delete/upload）必须加 `--allow-write`，且只允许 allowlist 内小号。
2. 小红书每次调用前重新注入新鲜 `XHS_COOKIE`（~10min / ~10 请求过期，24h 提醒无效）。
3. twitter 只经 `TWITTER_AUTH_TOKEN` + `TWITTER_CT0` env 注入（Cookie-Editor 手工导出；禁止 browser-cookie3 自动提取）。
4. bilibili 仅匿名只读（config `bilibili.anon: true`）；proxied 模式不可行（aiohttp 忽略 env 代理）→ 拒绝。
5. 冷/隔离状态下 `reach-guard status` 可见；`unlock` 仅解 quarantine，permanent 不可逆。
6. 直连检测：`reach-guard detect`（历史 + 进程）；每次收尾运行一次，结果必须为 0。

## 检测器语义

- 直连 `twitter|bili|opencli|yt-dlp|mcporter|curl|agent-reach` → 违规报警。
- `gh` → 豁免白名单，永不误报。
- 零配置模式直连（`curl r.jina.ai`、`mcporter call exa`）→ 违规报警（必须经 guard 的 allowlist/元命令路径）。
