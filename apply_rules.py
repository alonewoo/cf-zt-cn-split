#!/usr/bin/env python3
"""
脚本 B：从 GitHub 读取 cf_spilit_channel.txt 路由规则，写入 Cloudflare 设备分流策略

流程：
  1. 从 GitHub raw URL 读取 cf_spilit_channel.txt
  2. 解析 JSON 路由规则
  3. 应用 MAX_RULES 限制（超出则截断尾部 IP 规则）
  4. 通过 Cloudflare API PUT 写入设备策略

环境变量：
  CF_API_TOKEN    - Cloudflare API Token（需 Zero Trust 编辑权限）
  CF_ACCOUNT_ID   - Cloudflare Account ID
  CF_PROFILE_ID   - Device Profile ID（可选，留空则用默认策略）
  MODE            - exclude（CN直连）| include（只有CN走WARP）
  GITHUB_RAW_URL  - cf_spilit_channel.txt 的 raw 链接
                    例: https://raw.githubusercontent.com/owner/repo/main/cf_spilit_channel.txt
"""

import requests
import os
import json

# ════════════════════════════════════════════
# 配置区
# ════════════════════════════════════════════

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID   = os.getenv("CF_PROFILE_ID", "")
MODE         = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

GITHUB_RAW_URL = os.getenv("GITHUB_RAW_URL", "")

MAX_RULES = 4000
TIMEOUT = 30

# ── 环境变量校验 ──
if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

if not GITHUB_RAW_URL:
    raise ValueError("缺少环境变量 GITHUB_RAW_URL，请设置 cf_spilit_channel.txt 的 raw 链接")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}


# ════════════════════════════════════════════
# 功能函数
# ════════════════════════════════════════════

def fetch_rules_from_github():
    """从 GitHub raw URL 读取 cf_spilit_channel.txt 并解析为路由规则列表"""
    print("  [1/3] 从 GitHub 读取路由规则...")
    r = requests.get(GITHUB_RAW_URL, timeout=TIMEOUT)
    r.raise_for_status()

    rules = json.loads(r.text)

    # 统计
    preserved = sum(1 for r in rules if "address" in r and r.get("description", "") in
                    ("", "IPv6 Link Local", "DHCP Broadcast", "DHCP Unspecified"))
    domain_n = sum(1 for r in rules if "host" in r)
    ip_n = sum(1 for r in rules if "address" in r) - preserved

    print(f"        读取到 {len(rules)} 条规则"
          f"（保留 {preserved} | 域名 {domain_n} | IP {ip_n}）")
    return rules


def truncate_rules(rules):
    """
    应用 MAX_RULES 限制
    规则顺序为 [保留, 域名, IP]，截断时从尾部（IP 规则）开始裁剪
    """
    if len(rules) <= MAX_RULES:
        print(f"  [2/3] 规则总数 {len(rules)} ≤ {MAX_RULES}，无需截断")
        return rules

    truncated = rules[:MAX_RULES]
    removed = len(rules) - MAX_RULES
    print(f"  [2/3] 规则总数 {len(rules)} > {MAX_RULES}，已截断尾部 {removed} 条 IP 规则")
    return truncated


def update_split_tunnels(routes):
    """通过 Cloudflare API 更新设备分流策略"""
    print(f"  [3/3] 写入 Cloudflare（{len(routes)} 条路由, Mode: {MODE}）...")

    if PROFILE_ID:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/{PROFILE_ID}/{MODE}")
    else:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/{MODE}")

    resp = requests.put(url, json=routes, headers=HEADERS, timeout=60)

    if resp.status_code in (200, 204):
        print(f"  ✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"  ❌ 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()


# ════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  脚本 B: GitHub → Cloudflare 分流策略")
    print("=" * 60)

    # 1. 从 GitHub 读取规则
    rules = fetch_rules_from_github()

    # 2. 应用规则上限
    routes = truncate_rules(rules)

    # 3. 写入 Cloudflare
    update_split_tunnels(routes)

    print("\n  脚本 B 执行完毕。")


if __name__ == "__main__":
    main()
