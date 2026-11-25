#!/usr/bin/env python3
"""
High-performance cross-client routing rules compiler.
Compiles unified rule sources into optimized rulesets for:
  - Clash / Mihomo (.mrs binary + .list text + classical .yaml)
  - Stash (domain/ipcidr/classical .yaml + .stoverride)
  - Loon (.list + .plugin)
Zero third-party dependencies (Python 3.10+ stdlib only).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT_DIR / "config" / "sources.json"
TEMPLATES_DIR = ROOT_DIR / "templates"
DEFAULT_DIST_DIR = ROOT_DIR / "dist"

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)
SINGLE_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Rule types unsupported on iOS / Loon that should be stripped from Loon output
LOON_UNSUPPORTED_TYPES = {
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "UID",
    "NETWORK",
    "DSCP",
}


@dataclass
class RuleBucket:
    """Holds parsed rules categorized by matching behavior."""

    domain_exact: Set[str] = field(default_factory=set)
    domain_suffix: Set[str] = field(default_factory=set)
    ipv4: List[ipaddress.IPv4Network] = field(default_factory=list)
    ipv6: List[ipaddress.IPv6Network] = field(default_factory=list)
    # Classical rules that cannot be represented as pure domain or IP CIDR
    classical: List[Tuple[str, str]] = field(default_factory=list)
    raw_count: int = 0


def is_valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    if "." in value:
        return bool(DOMAIN_RE.match(value))
    # Allow single-label local hostnames like "localhost", "local", "lan"
    return bool(SINGLE_LABEL_RE.match(value))


def strip_comment(line: str) -> str:
    line = line.strip()
    if not line or line.startswith(("#", "//", ";")):
        return ""
    # Strip inline comments only if preceded by whitespace
    for marker in (" #", "\t#", " //", "\t//"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx].strip()
    return line


def parse_ip_network(
    raw: str,
) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def parse_lines(lines: Iterable[str], bucket: RuleBucket) -> None:
    """Parse Surge/Clash classical, Mihomo domain/ipcidr text, or raw CIDR lines."""
    for raw_line in lines:
        line = strip_comment(raw_line)
        if not line:
            continue

        # Handle YAML payload prefix if an upstream ever uses "- '...'"
        if line.startswith("- "):
            line = line[2:].strip().strip("'\"")
            if not line:
                continue

        # 1. Classical comma-separated format: TYPE,VALUE[,OPTIONS...]
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                continue
            rule_type = parts[0].upper()
            value = parts[1].strip()
            if not value:
                continue

            bucket.raw_count += 1
            if rule_type == "DOMAIN":
                dom = value.lower().strip(".")
                if is_valid_domain(dom):
                    bucket.domain_exact.add(dom)
            elif rule_type == "DOMAIN-SUFFIX":
                dom = value.lower().strip(".")
                if is_valid_domain(dom):
                    bucket.domain_suffix.add(dom)
            elif rule_type in ("IP-CIDR", "IP-CIDR6"):
                net = parse_ip_network(value)
                if net is not None:
                    if isinstance(net, ipaddress.IPv4Network):
                        bucket.ipv4.append(net)
                    else:
                        bucket.ipv6.append(net)
            elif rule_type in (
                "DOMAIN-KEYWORD",
                "DOMAIN-REGEX",
                "URL-REGEX",
                "USER-AGENT",
                "PROCESS-NAME",
                "PROCESS-PATH",
                "DST-PORT",
                "SRC-PORT",
            ):
                norm_val = value.lower() if rule_type == "DOMAIN-KEYWORD" else value
                bucket.classical.append((rule_type, norm_val))
            continue

        # 2. Mihomo domain wildcard format: "+.example.com" or ".example.com"
        if line.startswith("+.") or line.startswith("."):
            dom = line.lstrip("+.").lower().strip(".")
            if is_valid_domain(dom):
                bucket.raw_count += 1
                bucket.domain_suffix.add(dom)
            continue

        # 3. Raw IP / CIDR format
        net = parse_ip_network(line)
        if net is not None:
            bucket.raw_count += 1
            if isinstance(net, ipaddress.IPv4Network):
                bucket.ipv4.append(net)
            else:
                bucket.ipv6.append(net)
            continue

        # 4. Raw exact domain format (used by MetaCubeX geosite .list)
        dom = line.lower().strip(".")
        if is_valid_domain(dom):
            bucket.raw_count += 1
            bucket.domain_exact.add(dom)


def prune_domains(
    domain_suffix: Set[str], domain_exact: Set[str]
) -> Tuple[List[str], List[str]]:
    """
    Use a reverse-label Trie to prune redundant domains:
      - If "example.com" is a suffix, drop "sub.example.com" from both suffix and exact.
      - Deduplicate and sort cleanly.
    """
    trie: Dict[str, dict] = {}
    END = "__END__"

    # Sort suffixes by label count ascending so parent domains are inserted first
    sorted_suffixes = sorted(
        domain_suffix, key=lambda d: (d.count("."), d)
    )
    kept_suffixes: List[str] = []

    for dom in sorted_suffixes:
        labels = dom.split(".")[::-1]
        node = trie
        covered = False
        for label in labels:
            if END in node:
                covered = True
                break
            node = node.setdefault(label, {})
        if not covered and END not in node:
            node[END] = True
            kept_suffixes.append(dom)

    kept_exact: List[str] = []
    for dom in sorted(domain_exact):
        labels = dom.split(".")[::-1]
        node = trie
        covered = False
        for label in labels:
            if END in node:
                covered = True
                break
            if label not in node:
                break
            node = node[label]
        else:
            if END in node:
                covered = True
        if not covered:
            kept_exact.append(dom)

    kept_suffixes.sort()
    kept_exact.sort()
    return kept_suffixes, kept_exact


def collapse_ips(
    ipv4_list: List[ipaddress.IPv4Network], ipv6_list: List[ipaddress.IPv6Network]
) -> Tuple[List[str], List[str]]:
    v4 = [str(n) for n in ipaddress.collapse_addresses(ipv4_list)] if ipv4_list else []
    v6 = [str(n) for n in ipaddress.collapse_addresses(ipv6_list)] if ipv6_list else []
    return v4, v6


def fetch_url(url: str, timeout: int = 20, retries: int = 3) -> Tuple[str, List[str]]:
    last_err: Optional[Exception] = None
    headers = {"User-Agent": "routing-rules-builder/1.0"}
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
                return url, data.splitlines()
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            last_err = err
            if attempt < retries:
                continue
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_err}")


def fetch_all_upstreams(urls: Set[str]) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    if not urls:
        return results
    print(f"Fetching {len(urls)} unique upstream sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch_url, u): u for u in sorted(urls)}
        for fut in concurrent.futures.as_completed(futures):
            url, lines = fut.result()
            results[url] = lines
            print(f"  [OK] {url.rsplit('/', 1)[-1]} ({len(lines)} lines)")
    return results


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_yaml_payload(path: Path, items: List[str], header_comment: str) -> None:
    lines = [f"# {header_comment}", "payload:"]
    for item in items:
        escaped = item.replace("'", "''")
        lines.append(f"  - '{escaped}'")
    write_text(path, "\n".join(lines) + "\n")


def compile_mrs(mihomo_bin: str, behavior: str, src_list: Path, dst_mrs: Path) -> bool:
    cmd = [mihomo_bin, "convert-ruleset", behavior, "text", str(src_list), str(dst_mrs)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  [WARN] mihomo convert-ruleset failed for {src_list.name}: {res.stderr.strip()}")
        return False
    return True


def render_templates(base_url: str, updated_at: str, dist_dir: Path) -> List[Dict[str, str]]:
    rendered = []
    if not TEMPLATES_DIR.exists():
        return rendered
    clean_base = base_url.rstrip("/")
    out_dir = dist_dir / "templates"
    out_dir.mkdir(parents=True, exist_ok=True)

    meta_map = {
        "clash-mihomo.yaml": ("Clash / Mihomo 配置片段", "推荐：使用 .mrs 高性能二进制规则集"),
        "stash.stoverride": ("Stash 覆写模板", "支持 Stash 一键导入，无侵入挂载规则集"),
        "loon.plugin": ("Loon 插件模板", "支持 Loon 直接添加插件，自动同步规则集"),
    }

    for tpl in sorted(TEMPLATES_DIR.iterdir()):
        if not tpl.is_file():
            continue
        content = tpl.read_text(encoding="utf-8")
        content = content.replace("{{BASE_URL}}", clean_base)
        content = content.replace("{{UPDATED_AT}}", updated_at)
        write_text(out_dir / tpl.name, content)
        title, desc = meta_map.get(tpl.name, (tpl.name, ""))
        rendered.append(
            {
                "file": tpl.name,
                "title": title,
                "description": desc,
                "url": f"{clean_base}/templates/{tpl.name}",
                "rel": f"templates/{tpl.name}",
            }
        )
    return rendered


def generate_index_html(
    meta: dict,
    manifest: dict,
    dist_dir: Path,
) -> None:
    title = html.escape(meta.get("title", "Routing Rules"))
    desc = html.escape(meta.get("description", ""))
    base_url = manifest["base_url"].rstrip("/")
    updated_at = manifest["updated_at"]
    has_mrs = manifest["has_mrs"]

    cards_html: List[str] = []
    for rs in manifest["rulesets"]:
        rid = html.escape(rs["id"])
        rname = html.escape(rs["name"])
        rdesc = html.escape(rs["description"])
        stats = rs["stats"]
        files = rs["files"]

        pills: List[str] = []
        if stats["domain"] > 0:
            pills.append(f'<span class="pill">域名 {stats["domain"]:,}</span>')
        if stats["ip"] > 0:
            pills.append(f'<span class="pill">IP {stats["ip"]:,}</span>')
        if stats["classical"] > 0:
            pills.append(f'<span class="pill">Classical {stats["classical"]:,}</span>')
        if stats["saved_pct"] > 0:
            pills.append(
                f'<span class="pill pill-accent">去重压缩 -{stats["saved_pct"]:.1f}%</span>'
            )

        links: List[str] = []
        for label, rel_path, badge in files:
            full_url = f"{base_url}/{rel_path}"
            links.append(
                f"""
                <div class="link-row" data-client="{badge}">
                  <span class="badge badge-{badge}">{html.escape(label)}</span>
                  <a href="{html.escape(rel_path)}" target="_blank" rel="noopener">{html.escape(rel_path)}</a>
                  <button class="copy-btn" data-url="{html.escape(full_url)}">复制订阅</button>
                </div>
                """
            )

        cards_html.append(
            f"""
            <article class="card">
              <div class="card-head">
                <div>
                  <h3>{rname} <code>{rid}</code></h3>
                  <p class="muted">{rdesc}</p>
                </div>
                <div class="pills">{''.join(pills)}</div>
              </div>
              <div class="links">{''.join(links)}</div>
            </article>
            """
        )

    tpl_client_map = {
        "clash-mihomo.yaml": "mihomo",
        "stash.stoverride": "stash",
        "loon.plugin": "loon",
    }
    tpl_cards: List[str] = []
    for tpl in manifest["templates"]:
        c_tag = tpl_client_map.get(tpl["file"], "all")
        tpl_cards.append(
            f"""
            <div class="tpl-card" data-client="{c_tag}">
              <div>
                <div class="tpl-title">
                  <span class="badge badge-{c_tag}">{html.escape(c_tag.upper())}</span>
                  <strong>{html.escape(tpl['title'])}</strong>
                </div>
                <div class="muted">{html.escape(tpl['description'])}</div>
              </div>
              <div class="tpl-actions">
                <a class="btn-link" href="{html.escape(tpl['rel'])}" target="_blank" rel="noopener">预览</a>
                <button class="copy-btn primary" data-url="{html.escape(tpl['url'])}">复制订阅链接</button>
              </div>
            </div>
            """
        )

    mrs_badge = (
        '<span class="status ok">.mrs 二进制已启用</span>'
        if has_mrs
        else '<span class="status warn">本地预览（CI 自动编译 .mrs）</span>'
    )

    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b1120;
      --surface: #131c31;
      --surface-hover: #1a2642;
      --border: #24324d;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --ok: #22c55e;
      --warn: #f59e0b;
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #f8fafc;
        --surface: #ffffff;
        --surface-hover: #f1f5f9;
        --border: #e2e8f0;
        --text: #0f172a;
        --muted: #64748b;
        --accent: #0284c7;
        --ok: #16a34a;
        --warn: #d97706;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    .container {{ max-width: 960px; margin: 0 auto; padding: 36px 20px 72px; }}
    header {{ margin-bottom: 24px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; letter-spacing: -0.02em; }}
    h2 {{ margin: 30px 0 12px; font-size: 17px; font-weight: 600; }}
    h3 {{ margin: 0 0 4px; font-size: 16px; display: flex; align-items: center; gap: 8px; }}
    code {{
      font-size: 12px; padding: 2px 7px; border-radius: 6px;
      background: rgba(148, 163, 184, 0.16); color: var(--accent);
    }}
    .muted {{ color: var(--muted); font-size: 13px; margin: 0; }}
    .meta-bar {{
      display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
      margin-top: 12px; font-size: 13px; color: var(--muted);
    }}
    .status {{ padding: 2px 10px; border-radius: 999px; font-weight: 600; font-size: 12px; }}
    .status.ok {{ background: rgba(34, 197, 94, 0.15); color: var(--ok); }}
    .status.warn {{ background: rgba(245, 158, 11, 0.15); color: var(--warn); }}
    .tabs {{
      display: inline-flex; flex-wrap: wrap; gap: 6px; padding: 4px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; margin-top: 18px;
    }}
    .tab-btn {{
      border: none; background: transparent; color: var(--muted);
      padding: 6px 14px; border-radius: 7px; font-size: 13px; font-weight: 600;
      cursor: pointer; transition: all 0.15s ease;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{ background: var(--accent); color: #ffffff; }}
    .grid {{ display: grid; gap: 12px; }}
    .card, .tpl-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }}
    .card-head {{
      display: flex; justify-content: space-between; align-items: flex-start;
      gap: 12px; flex-wrap: wrap; margin-bottom: 12px;
    }}
    .pills {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .pill {{
      font-size: 12px; padding: 2px 8px; border-radius: 999px;
      background: rgba(148, 163, 184, 0.14); color: var(--text);
    }}
    .pill-accent {{ background: rgba(56, 189, 248, 0.16); color: var(--accent); }}
    .links {{ display: grid; gap: 8px; }}
    .link-row {{
      display: grid; grid-template-columns: 122px 1fr auto; gap: 10px;
      align-items: center; font-size: 13px;
      padding: 6px 8px; border-radius: 8px;
    }}
    .link-row:hover {{ background: var(--surface-hover); }}
    .link-row a {{
      color: var(--text); text-decoration: none; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap;
      font-family: ui-monospace, SFMono-Regular, monospace;
    }}
    .link-row a:hover {{ color: var(--accent); text-decoration: underline; }}
    .badge {{
      display: inline-block; text-align: center; font-size: 11px; font-weight: 600;
      padding: 2px 8px; border-radius: 6px;
    }}
    .badge-mihomo {{ background: rgba(56, 189, 248, 0.18); color: var(--accent); }}
    .badge-stash {{ background: rgba(168, 85, 247, 0.18); color: #c084fc; }}
    .badge-loon {{ background: rgba(34, 197, 94, 0.18); color: var(--ok); }}
    .copy-btn, .btn-link {{
      border: 1px solid var(--border); background: transparent; color: var(--text);
      border-radius: 8px; padding: 5px 11px; font-size: 12px; cursor: pointer;
      text-decoration: none; font-weight: 500; white-space: nowrap;
    }}
    .copy-btn.primary {{
      background: var(--accent); border-color: var(--accent); color: #ffffff;
    }}
    .copy-btn.primary:hover {{ opacity: 0.9; color: #ffffff; }}
    .copy-btn:hover, .btn-link:hover {{ border-color: var(--accent); color: var(--accent); }}
    .tpl-card {{
      display: flex; justify-content: space-between; align-items: center;
      gap: 12px; flex-wrap: wrap;
    }}
    .tpl-title {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
    .tpl-actions {{ display: flex; gap: 8px; }}
    .hidden {{ display: none !important; }}
    @media (max-width: 640px) {{
      .link-row {{ grid-template-columns: 100px 1fr auto; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{title}</h1>
      <p class="muted">{desc}</p>
      <div class="meta-bar">
        <span>最近更新：{html.escape(updated_at)} (UTC)</span>
        <span>规则集：{len(manifest['rulesets'])} 组</span>
        {mrs_badge}
      </div>
      <div class="tabs" role="tablist" aria-label="选择客户端">
        <button class="tab-btn active" data-filter="all">全部客户端</button>
        <button class="tab-btn" data-filter="mihomo">Clash / Mihomo</button>
        <button class="tab-btn" data-filter="stash">Stash</button>
        <button class="tab-btn" data-filter="loon">Loon</button>
      </div>
    </header>

    <h2>一键订阅模板</h2>
    <div class="grid">{''.join(tpl_cards)}</div>

    <h2>分流规则集订阅</h2>
    <div class="grid">{''.join(cards_html)}</div>
  </div>

  <script>
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {{
      tab.addEventListener('click', () => {{
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const filter = tab.getAttribute('data-filter');
        document.querySelectorAll('[data-client]').forEach(el => {{
          const client = el.getAttribute('data-client');
          el.classList.toggle('hidden', filter !== 'all' && client !== filter);
        }});
      }});
    }});

    document.querySelectorAll('.copy-btn').forEach(btn => {{
      btn.addEventListener('click', async () => {{
        const url = btn.getAttribute('data-url');
        try {{
          await navigator.clipboard.writeText(url);
          const old = btn.textContent;
          btn.textContent = '已复制 ✓';
          setTimeout(() => btn.textContent = old, 1400);
        }} catch {{
          prompt('请手动复制订阅链接：', url);
        }}
      }});
    }});
  </script>
</body>
</html>
"""
    write_text(dist_dir / "index.html", page)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build optimized cross-client routing rules.")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--dist", type=Path, default=DEFAULT_DIST_DIR)
    parser.add_argument("--base-url", type=str, default=os.environ.get("PAGES_BASE_URL", ""))
    parser.add_argument("--mihomo-bin", type=str, default=os.environ.get("MIHOMO_BIN", ""))
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    meta = config.get("meta", {})
    base_url = (args.base_url or meta.get("default_base_url", "")).rstrip("/")
    updated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    mihomo_bin = args.mihomo_bin or shutil.which("mihomo") or ""
    if mihomo_bin and not Path(mihomo_bin).exists():
        mihomo_bin = ""
    if mihomo_bin:
        print(f"Using mihomo binary for .mrs compilation: {mihomo_bin}")
    else:
        print("mihomo binary not found; skipping .mrs compilation (text/yaml outputs still built).")

    dist_dir: Path = args.dist
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True, exist_ok=True)
    # Prevent GitHub Pages Jekyll from ignoring files/folders
    write_text(dist_dir / ".nojekyll", "")

    # Gather all unique upstream URLs and fetch concurrently
    all_urls: Set[str] = set()
    for rs in config["rulesets"]:
        all_urls.update(rs.get("upstreams", []))
    upstream_cache = fetch_all_upstreams(all_urls)

    manifest_rulesets = []
    any_mrs = False

    print("\nCompiling & optimizing rulesets...")
    for rs in config["rulesets"]:
        rid = rs["id"]
        bucket = RuleBucket()

        # Load local custom rules
        for local_rel in rs.get("local", []):
            local_path = ROOT_DIR / local_rel
            if local_path.exists():
                parse_lines(local_path.read_text(encoding="utf-8").splitlines(), bucket)

        # Load upstream rules
        for url in rs.get("upstreams", []):
            parse_lines(upstream_cache.get(url, []), bucket)

        # Optimize: Trie prune domains + collapse IP CIDRs + deduplicate classical
        kept_suffixes, kept_exact = prune_domains(bucket.domain_suffix, bucket.domain_exact)
        kept_v4, kept_v6 = collapse_ips(bucket.ipv4, bucket.ipv6)
        kept_classical = sorted(set(bucket.classical))

        domain_payload = [f"+.{d}" for d in kept_suffixes] + kept_exact
        ip_payload = kept_v4 + kept_v6

        opt_count = len(domain_payload) + len(ip_payload) + len(kept_classical)
        saved_pct = (
            max(0.0, (bucket.raw_count - opt_count) / bucket.raw_count * 100.0)
            if bucket.raw_count > 0
            else 0.0
        )

        files_index: List[Tuple[str, str, str]] = []
        header = f"{rid} | updated: {updated_at} UTC | domains: {len(domain_payload)}, ips: {len(ip_payload)}, classical: {len(kept_classical)}"

        # 1. Mihomo outputs (domain/ip text + .mrs binary + optional classical yaml)
        if domain_payload:
            rel_txt = f"mihomo/{rid}-domain.list"
            src_txt = dist_dir / rel_txt
            write_text(src_txt, "\n".join(domain_payload) + "\n")
            if mihomo_bin:
                rel_mrs = f"mihomo/{rid}-domain.mrs"
                if compile_mrs(mihomo_bin, "domain", src_txt, dist_dir / rel_mrs):
                    any_mrs = True
                    files_index.append(("Mihomo .mrs", rel_mrs, "mihomo"))
            files_index.append(("Mihomo Domain", rel_txt, "mihomo"))

        if ip_payload:
            rel_txt = f"mihomo/{rid}-ip.list"
            src_txt = dist_dir / rel_txt
            write_text(src_txt, "\n".join(ip_payload) + "\n")
            if mihomo_bin:
                rel_mrs = f"mihomo/{rid}-ip.mrs"
                if compile_mrs(mihomo_bin, "ipcidr", src_txt, dist_dir / rel_mrs):
                    any_mrs = True
                    files_index.append(("Mihomo IP .mrs", rel_mrs, "mihomo"))
            files_index.append(("Mihomo IP", rel_txt, "mihomo"))

        if kept_classical:
            rel_cls = f"mihomo/{rid}-classical.yaml"
            cls_items = [f"{t},{v}" for t, v in kept_classical]
            write_yaml_payload(dist_dir / rel_cls, cls_items, header)
            files_index.append(("Mihomo Classical", rel_cls, "mihomo"))

        # 2. Stash outputs (split domain/ip YAML for performance + combined classical YAML)
        if domain_payload:
            rel_s_dom = f"stash/{rid}-domain.yaml"
            write_yaml_payload(dist_dir / rel_s_dom, domain_payload, header)
            files_index.append(("Stash Domain", rel_s_dom, "stash"))

        if ip_payload:
            rel_s_ip = f"stash/{rid}-ip.yaml"
            write_yaml_payload(dist_dir / rel_s_ip, ip_payload, header)
            files_index.append(("Stash IP", rel_s_ip, "stash"))

        ios_classical = [
            f"{t},{v}" for t, v in kept_classical if t not in LOON_UNSUPPORTED_TYPES
        ]
        if ios_classical:
            rel_s_cls = f"stash/{rid}-classical.yaml"
            write_yaml_payload(dist_dir / rel_s_cls, ios_classical, header)
            files_index.append(("Stash Classical", rel_s_cls, "stash"))

        stash_combined: List[str] = []
        stash_combined.extend(f"DOMAIN-SUFFIX,{d}" for d in kept_suffixes)
        stash_combined.extend(f"DOMAIN,{d}" for d in kept_exact)
        stash_combined.extend(ios_classical)
        stash_combined.extend(f"IP-CIDR,{ip},no-resolve" for ip in kept_v4)
        stash_combined.extend(f"IP-CIDR6,{ip},no-resolve" for ip in kept_v6)
        rel_s_all = f"stash/{rid}.yaml"
        write_yaml_payload(dist_dir / rel_s_all, stash_combined, header)
        files_index.append(("Stash 合集", rel_s_all, "stash"))

        # 3. Loon outputs (.list pure text, iOS-compatible, auto no-resolve)
        loon_lines = [f"# {header}"] + stash_combined
        rel_loon = f"loon/{rid}.list"
        write_text(dist_dir / rel_loon, "\n".join(loon_lines) + "\n")
        files_index.append(("Loon .list", rel_loon, "loon"))

        print(
            f"  [{rid:10s}] raw={bucket.raw_count:6d} -> opt={opt_count:6d} "
            f"(domain={len(domain_payload)}, ip={len(ip_payload)}, classical={len(kept_classical)}, -{saved_pct:.1f}%)"
        )

        manifest_rulesets.append(
            {
                "id": rid,
                "name": rs["name"],
                "category": rs.get("category", "other"),
                "description": rs.get("description", ""),
                "stats": {
                    "raw": bucket.raw_count,
                    "optimized": opt_count,
                    "domain": len(domain_payload),
                    "ip": len(ip_payload),
                    "classical": len(kept_classical),
                    "saved_pct": round(saved_pct, 2),
                },
                "files": files_index,
            }
        )

    templates_meta = render_templates(base_url, updated_at, dist_dir)
    manifest = {
        "updated_at": updated_at,
        "base_url": base_url,
        "has_mrs": any_mrs,
        "templates": templates_meta,
        "rulesets": manifest_rulesets,
    }
    write_text(
        dist_dir / "manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )
    generate_index_html(meta, manifest, dist_dir)
    print(f"\nBuild complete -> {dist_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
