# wrapped_binaries.md — 包装二进制集 + PATH shim 规范

## 8 个被包装二进制（全部收敛到 `reach-guard run`）

| 二进制 | 平台解析 | 后端/代理方式 | 本机位置 |
|---|---|---|---|
| `agent-reach` | meta（doctor/install/check-update/configure） | — | pipx venv（`agent-reach.real`） |
| `twitter` | twitter | env（HTTP(S)_PROXY） | uv twitter-cli（`twitter.real`） |
| `bili` | bilibili | reject（aiohttp 忽略 env）→ 仅匿名只读 | uv bilibili-cli（`bili.real`） |
| `opencli` | argv[1] adapter → 平台；meta（list/profile/doctor） | profile（Chrome profile 必选） | /opt/homebrew/bin/opencli |
| `gh` | github（豁免：仅日志透传） | env | `gh.real` |
| `yt-dlp` | youtube（bilibili URL → 拒绝 exit 6） | env | /opt/homebrew/Caskroom/miniconda/base/bin/yt-dlp |
| `mcporter` | exa.* → websearch；meta | env | /opt/homebrew/bin/mcporter |
| `curl` | URL host → 平台表 / curl-allowlist（r.jina.ai、api.ipify.org、v2ex.com） | env | /usr/bin/curl |

## 原二进制备份命名 `<bin>.real`

- shim 安装脚本（`reach-guard shims install`，幂等）把 `~/.local/bin/<bin>` 改名为
  `<bin>.real` 再放置 shim；符号链接整链移动，uv/pipx venv 不受破坏。
- 系统位置（`/usr/bin/curl`、`/opt/homebrew/bin/{opencli,mcporter}`、conda yt-dlp）
  **永不被移动**；wrapper 运行时 PATH 解析（跳过 `~/.local/bin` 两处 shim 目录），
  找不到 → fail-closed exit 8 + 安装指引。
- `agent-reach` 前置安装：`pipx install --python <py>=3.11+ https://github.com/Panniantong/agent-reach/archive/main.zip`
  （docs/install.md）。

## 平台解析规则（argv[0]+argv[1]）

- `bili <sub>` → bilibili；`twitter <sub>` → twitter。
- `opencli <adapter>` → 表中 adapter（xiaohongshu/douyin/weibo/bilibili/twitter/
  instagram/facebook/reddit/youtube/xueqiu/xiaoyuzhou/linkedin）；未知 adapter → exit 6。
- `curl <url>` → host 映射；平台表外且不在 allowlist → exit 8。
- `yt-dlp <url>` → youtube；bilibili URL → exit 6（路由到 `bili`）。
- `mcporter call exa.*` → websearch；其他 tool → exit 6。
- 未知二进制 / 无法解析 → **exit 8 fail-closed**。

## 未知二进制 / 表外平台

未知二进制 → exit 8；表外平台（strict 表未注册）→ exit 6。绝不放行。
