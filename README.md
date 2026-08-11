# reach-guard

Strict-mode enforcement wrapper for agent-reach and its upstream binaries
(`agent-reach|twitter|bili|opencli|gh|yt-dlp|mcporter|curl`). Python 3.11+,
**stdlib only** (zero runtime dependencies). **Never modifies agent-reach or
any upstream source/config/storage.**

Goal: reduce the probability and severity of platform account bans (limit /
captcha downgrade). **Not a promise of immunity** — device-fingerprint / CDP
detection (e.g. 2026 Xiaohongshu #915) is out of scope.

---

## Strict semantics (default and only mode)

- **Global serial**: fcntl serial lock, concurrency = 1, ≥5s between ANY two calls.
- **Pacing**: per-platform min interval + jitter (clock-based, drift-free, rollback-safe).
- **Quota**: hourly + daily + session-batch token buckets, persisted (60d rotation).
- **Proxy binding**: residential/static only; account↔IP binding; egress check via
  neutral endpoint (`api.ipify.org`, 10s); drift → exit 3; **geo-match** proxy IP
  country vs account locale → mismatch exit 3.
- **Circuit breaker**: signal → tier triple mapping — `cooldown` (platform 24h) /
  `quarantine` (account+platform, 2nd strike in 7d, manual `unlock`) /
  `permanent` (ban-class keywords, irreversible). Context whitelist for benign
  anonymous text never trips. Douyin 200-empty honeypot heuristic.
- **Session**: account allowlist (SHA-256 hashes of env credentials only);
  reads default, writes need `--allow-write`; cookie gate (xhs fresh per session,
  twitter/bili explicit env only, no browser-cookie3); per-account Chrome profiles.
- **Time windows**: deny 23:00-09:00 and 19:00-22:00 (Asia/Shanghai), per-platform
  overridable → exit 5.
- **No `--relaxed`**, no silent downgrade. Unknown platform → exit 6; unknown
  binary → exit 8. Breaker wins over upstream error (exit 7).

### Strict platform table (most conservative; hourly = daily/12 where not explicit)

| 平台 | 间隔 | 时/日/批配额 | 冷却信号(节选) | IP | 代理方式 |
|---|---|---|---|---|---|
| 小红书 | 10s±3s | 5/50/10 | 461/124/验证码/AI操作/登录已过期/请求过于频繁/406 | 静态住宅绑定 | opencli→profile 必选 |
| 抖音 | 30s±10s | 8/100/30 | 200-空/2483/account blocked/请先登录 | 静态住宅绑定 | opencli→profile 必选 |
| 微博 | 30s±10s | 8/100/30 | 432/异常冻结/频繁/geetest/验证码 | 固定住宅单IP | opencli→profile 必选 |
| B站 | 10s±3s | 16/200/50 | 412/-352/风控校验失败/1003/-401 | 住宅绑定 | **bili-cli 代理不可行→仅匿名只读，否则 exit 3** |
| Twitter | 60s±20s | 4/50/10 | 封号/受限/429/异常 | 住宅(禁DC) | twitter-cli→env ✓ |
| Instagram | 60s±20s | 2/20/5 | 429/login required/请重新登录 | Chrome profile | opencli→profile 必选 |
| Facebook | 60s±20s | 2/20/5 | 429/checkpoint/异常登录 | Chrome profile | opencli→profile 必选 |
| Reddit | 30s±10s | 8/100/20 | 403/blocked/rate | 可选住宅 | env（未验证）/profile |
| LinkedIn | 60s±20s | 2/20/5 | 受限/异常/请验证 | 住宅 | env（undici 未验证）|
| YouTube | 30s±10s | 8/100/20 | 机器人校验/429 | 可选 | yt-dlp→env ✓ |
| 微信(sogou) | 30s±10s | 4/50/10 | -2041/-2012/验证码/风控 | 住宅绑定 | curl→env ✓ |
| 雪球 | 30s±10s | 4/50/10 | 400/风控 | 住宅绑定 | opencli→profile 必选 |
| 小宇宙 | 30s±10s | 4/50/10 | 401/token 失效 | 住宅绑定 | curl→env ✓ |
| GitHub | 豁免 | 官方 5000/hr | — | — | gh→env（仅日志透传） |
| V2EX | 5s±2s | 41/500/20 | 429/403 | 可选 | curl→env ✓ |

> **假设值标注**: Instagram/Facebook/LinkedIn 配额无实证数字，取最保守假设。
> Reddit `rdt-cli`、LinkedIn `undici` 的 env 代理行为未实机验证；不可行即拒绝。

## 操作手册

```bash
reach-guard shims install        # 装 8 个 PATH shim（原二进制 → <bin>.real，幂等）
reach-guard run <bin> <args>     # 受管调用
reach-guard run --dry-run <bin> <args>   # 全链路预演，不执行上游
reach-guard doctor               # 健康检查（含真实 agent-reach doctor，如已安装）
reach-guard status               # strict 全项 + 配额 + 冷却 + 账本
reach-guard profile --platform <p> --account <a>   # 按账号隔离 Chrome profile(0700)
reach-guard account add <platform> [--label <l>]   # 注册当前 env 凭据哈希（不存原文）
reach-guard account list|rm <platform> [<account>]
reach-guard unlock <platform> <account>            # 人工解 quarantine（permanent 不可解）
reach-guard quarantine          # 列出冷却/隔离
reach-guard detect              # 直连检测（历史+进程；gh 豁免）
```

### 冷却/隔离操作流程

1. `reach-guard run ...` 触发风控信号 → exit 7 + 平台 24h cooldown。
2. 7 天内同账号同平台二次命中 → quarantine（账号+平台隔离）。
3. 人工确认风险已消除 → `reach-guard unlock <platform> <account>`。
4. 封禁类关键词（封号/封禁/冻结/永久/blocked/banned/suspended/locked/受限/attestation/验证异常）
   → permanent，`unlock` 拒绝（不可逆）。

### 退出码

| 码 | 含义 |
|---|---|
| 0 | ok |
| 2 | 配置错误 |
| 3 | IP（代理绑定/出口漂移/geo 不匹配/bili 代理模式） |
| 4 | 串行锁超时 |
| 5 | 配额·时段 |
| 6 | 会话（cookie 门禁/allowlist/写门禁/表外平台） |
| 7 | 熔断（**优先于上游错误**） |
| 8 | 上游缺失·错误 |

优先级：**breaker(7) > 上游错误(8)**；`run` 全链任何中间步骤中止则绝不调用上游。

## 故障排查

- `reach-guard run agent-reach doctor` → exit 8：二进制缺失。安装：
  `pipx install --python <python3.11+> https://github.com/Panniantong/agent-reach/archive/main.zip`。
- `reach-guard run bili ...` → exit 3：proxied 模式。设 `bilibili.anon: true`（匿名只读）。
- `reach-guard run opencli xiaohongshu ...` → exit 6：未注入新鲜 `XHS_COOKIE`。
- binding 平台无代理配置 → exit 3：**这是预期 fail-closed，不是 bug**。
- 状态文件损坏：`state.jsonl` 损坏行自动跳过，不崩。
- 时钟回拨：pacing 取 max(0, …)，不产生负等待。

## 非目标 (Must-NOT)

- 不修改 agent-reach / 上游源码、配置语义、存储格式；不新增凭据副本（凭据只经 env
  注入；OpenCLI 专用 Chrome profile 0700 为显式豁免载体）。
- 不规避设备指纹 / 行为模型 / CDP 检测；不承诺免封。
- 不绕过平台 ToS；不替代官方开放平台 L0 合规路径。
- 无 `--relaxed`；表外平台 exit 6，未知二进制 exit 8，绝不放行。

## 已知绕过面（高级用户须知，非缺陷）

守卫约束的是 **agent 的默认调用路径**（防意外刷量/注入劫持），不是对本地恶意进程的
安全边界。以下路径天然存在且与守卫等价：

- 直接调用 `<bin>.real`（守卫安装时原二进制改名）或绝对路径调用（PATH shim 不拦截
  绝对路径，如 `/usr/bin/curl`）；剥离 PATH 同理。
- `REACH_GUARD_DISPATCH_BIN=<bin>` 环境变量（自递归绕过标记）：同二进制重入时守卫
  直接 exec 真实二进制。这是 fork-bomb 防御的副产物，任何能写环境变量的调用者
  （agent/用户）都可触发——与上述 `.real`/绝对路径绕过同等强度，无新增能力。

按纪律约束 agent 即可（SKILL 常驻规则第 7 条：不要绕过 guard 直呼裸二进制）。


## 已知指纹面

- **TLS 指纹**：bili-cli（aiohttp）使用 stock Python TLS，无 impersonation——
  属已知指纹面；其影响由匿名只读 + 严格节奏部分对冲，不承诺免疫。
- IG/FB/LinkedIn 配额为假设值（无实证数字）。
