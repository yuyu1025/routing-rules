# Routing Rules

基于 **GitHub Actions + GitHub Pages** 的跨端高效分流规则仓库，一套规则源自动编译优化并分发给 **Clash (Mihomo)**、**Stash**、**Loon**。

## 特性

- **单一源维护**：只需维护 `rules/` 下的 4 个精简自定义文件，其余由 `config/sources.json` 自动拉取 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 每日定时同步。
- **高效规则优化**：
  - **域名 Trie 剪枝**：自动剔除已被父级 `DOMAIN-SUFFIX` 覆盖的子域名与重复项。
  - **IP CIDR 聚合**：自动合并重叠和相邻的 IPv4 / IPv6 网段。
  - **防 DNS 泄漏**：自动为 IP 规则补全 `no-resolve`。
- **三端最优格式**：
  - **Clash / Mihomo**：CI 自动编译 `.mrs` 二进制规则集（低内存、毫秒级加载）。
  - **Stash**：拆分 `domain` / `ipcidr` 高性能 YAML，附带 `.stoverride` 一键覆写模板。
  - **Loon**：纯净 `.list` 格式（自动剔除 iOS 不支持的规则类型），附带 `.plugin` 插件模板。
- **自带可视化导航页**：访问 <https://proxy.distinctive.fun/routing/> 即可查看规则统计与一键复制各端订阅链接。

## 内置规则集

| 规则集 ID | 说明 |
| :--- | :--- |
| `direct` | 自定义最高优先级直连白名单（内网 + 防误杀） |
| `proxy` | 自定义最高优先级代理名单 |
| `ai` | OpenAI / ChatGPT、Claude、Gemini、xAI/Grok、Perplexity、Cursor、Copilot 等 |
| `streaming` | 国际流媒体合集（YouTube / Netflix / Disney+ / TikTok / Spotify / HBO / Hulu / Prime Video / Bahamut / BiliIntl） |
| `youtube` / `netflix` / `disney` / `tiktok` / `spotify` | 独立流媒体规则集，方便按地区节点精细分流 |
| `telegram` | Telegram 域名与数据中心 IP 段 |
| `cn` | 国内直连（中国大陆域名、Apple CN、内网域名 + CN/私有 IP 段） |

## 首次启用步骤

1. 将本仓库推送到你的 GitHub（需设为 **Public** 仓库以免费使用 GitHub Pages）。
2. 打开仓库 **Settings → Pages → Build and deployment → Source**，选择 **GitHub Actions**。
3. 在 **Actions** 页面手动触发一次 **Build & Deploy Routing Rules**（或推送任意提交）。
4. 部署完成后访问 <https://proxy.distinctive.fun/routing/> 即可复制规则集或客户端模板链接。

## 自定义域名

正式入口是 `https://proxy.distinctive.fun/routing/`，由两部分组成：

| 组件 | 作用 |
| :--- | :--- |
| GitHub Pages | 源站，实际构建产物部署在 `https://yuyu1025.github.io/routing-rules/`（`build_type: workflow`） |
| Cloudflare Worker | `infra/site-proxy/`，挂在路由 `proxy.distinctive.fun/*` 上，把 `/routing/*` 反代到 GitHub Pages 的 `/routing-rules/*` |

GitHub Pages 无法把项目站点挂到自定义域名的**子路径**上（自定义域名只能占根路径），所以这里用 Worker 做前缀重写；DNS 侧只需一条代理记录（`AAAA 100::`，橙云），流量由 Workers 路由接管。

### 部署 / 更新代理

```bash
cd infra/site-proxy
npm install
CLOUDFLARE_ACCOUNT_ID=d68615c4b79a81e7cf83dff92d97560a npx wrangler deploy
```

CI 构建时通过 `--base-url https://proxy.distinctive.fun/routing` 把 manifest、模板里的绝对链接（订阅地址）统一指向自定义域名；页面内导航保持相对路径，因此在 `github.io` 与自定义域名下都能正常浏览。

## 日常维护

- **临时加一个直连或代理域名**：直接编辑 `rules/direct.list`、`rules/proxy.list`、`rules/ai.list` 或 `rules/streaming.list`，提交推送即可在 1 分钟内自动更新。
- **本地试跑构建**：
  ```bash
  python3 scripts/build.py
  ```
  构建产物输出至 `dist/` 目录（零外部依赖，仅需 Python 3.10+）。

> **安全提醒**：请勿在公开仓库中写入任何机场订阅链接、节点密码或个人敏感内网隐私信息。
