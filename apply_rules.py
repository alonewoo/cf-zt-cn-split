#!/usr/bin/env python3
"""
脚本 B：从 GitHub 读取 cf_spilit_channel.txt 路由规则，写入 Cloudflare 设备分流策略

流程：
  1. 从 GitHub 读取 cf_spilit_channel.txt（域名带 *. 通配符）
  2. 解析 JSON 路由规则
  3. 准备 Split Tunnel 规则：原样保留（域名保留 *. 通配符，IP 保留原样）
  4. 准备 Fallback Domains 规则：域名去除通配符，DNS 统一 223.5.5.5
  5. 应用 MAX_RULES 限制（仅对 Split Tunnel，超出则截断尾部 IP 规则）
  6. 通过 Cloudflare API 写入 Split Tunnel 策略
  7. 通过 Cloudflare API 写入 Fallback Domains 策略

环境变量：
  CF_API_TOKEN    - Cloudflare API Token（需 Zero Trust 编辑权限）
  CF_ACCOUNT_ID   - Cloudflare Account ID
  CF_PROFILE_ID   - Device Profile ID（可选，留空则用默认策略）
  MODE            - exclude（CN直连）| include（只有CN走WARP）
  GITHUB_RAW_URL  - cf_spilit_channel.txt 的 raw 链接
  FALLBACK_DNS    - Fallback 域名解析 DNS 服务器，默认 223.5.5.5
"""

import requests
import os
import json

# ════════════════════════════════════════════
# 配置区
# ════════════════════════════════════════════

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
ACCOUNT_ID     = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID     = os.getenv("CF_PROFILE_ID", "")
MODE           = os.getenv("MODE", "exclude")
ALLOWED_MODES  = {"exclude", "include"}
GITHUB_RAW_URL = os.getenv("GITHUB_RAW_URL", "")
FALLBACK_DNS   = os.getenv("FALLBACK_DNS", "223.5.5.5")

MAX_RULES = 4000
TIMEOUT   = 30

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
# 步骤 1：从 GitHub 读取规则
# ════════════════════════════════════════════

def fetch_rules_from_github():
    """
    从 GitHub raw URL 读取 cf_spilit_channel.txt 并解析为路由规则列表

    文件中的域名规则形如:
      {"host": "*.jd.com", "description": "京东 Domain"}
    IP 规则形如:
      {"address": "10.0.0.0/8", "description": ""}
    """
    print("  [1/5] 从 GitHub 读取路由规则...")

    r = requests.get(GITHUB_RAW_URL, timeout=TIMEOUT)
    r.raise_for_status()
    rules = json.loads(r.text)

    # 统计原始规则构成
    preserved = sum(1 for r in rules if "address" in r and r.get("description", "") in
                    ("", "IPv6 Link Local", "DHCP Broadcast", "DHCP Unspecified"))
    domain_n = sum(1 for r in rules if "host" in r)
    ip_n = sum(1 for r in rules if "address" in r) - preserved

    print(f"        读取到 {len(rules)} 条规则"
          f"（保留 {preserved} | 域名 {domain_n} | IP {ip_n}）")
    return rules


# ════════════════════════════════════════════
# 步骤 2：处理规则（生成两份独立清单）
# ════════════════════════════════════════════

def strip_wildcard(host):
    """
    去除通配符前缀：*.jd.com → jd.com
    仅用于 Fallback Domains，不影响 Split Tunnel
    """
    if host.startswith("*."):
        return host[2:]
    return host


def process_rules(rules):
    """
    将原始规则处理为两份独立清单：

    1. split_tunnel_rules — 原样保留，域名带 *. 通配符
       用于写入 Split Tunnel 策略
    2. fallback_rules — 域名去除通配符，绑定 DNS 223.5.5.5
       用于写入 Fallback Domains 策略
       仅包含域名规则，IP 规则不参与

    返回: (split_tunnel_rules, fallback_rules)
    """
    print("  [2/5] 处理规则（Split Tunnel 原样 + Fallback 去通配符）...")

    split_tunnel_rules = []
    fallback_rules = []
    domain_count = 0
    ip_count = 0

    for rule in rules:
        if "host" in rule:
            # ── 域名规则 ──

            # Split Tunnel：原样保留，通配符不处理
            split_tunnel_rules.append(rule)

            # Fallback Domains：去除通配符 + 绑定 DNS
            domain = strip_wildcard(rule["host"])
            fallback_rules.append({
                "domain": domain,
                "description": rule.get("description", ""),
                "dns_server": FALLBACK_DNS
            })
            domain_count += 1

        elif "address" in rule:
            # ── IP 规则：仅加入 Split Tunnel，不参与 Fallback ──
            split_tunnel_rules.append(rule)
            ip_count += 1

    print(f"        Split Tunnel: {len(split_tunnel_rules)} 条（域名 {domain_count} 带 *. | IP {ip_count}）")
    print(f"        Fallback:     {len(fallback_rules)} 条（域名 {domain_count} 去通配符 | DNS: {FALLBACK_DNS}）")

    return split_tunnel_rules, fallback_rules


# ════════════════════════════════════════════
# 步骤 3：应用规则上限
# ════════════════════════════════════════════

def truncate_rules(rules):
    """
    应用 MAX_RULES 限制（仅对 Split Tunnel 生效）

    规则顺序为 [保留, 域名, IP]，截断时从尾部（IP 规则）开始裁剪
    Fallback Domains 不受此限制（域名规则数量远小于 4000）
    """
    if len(rules) <= MAX_RULES:
        print(f"  [3/5] Split Tunnel 规则总数 {len(rules)} <= {MAX_RULES}，无需截断")
        return rules

    truncated = rules[:MAX_RULES]
    removed = len(rules) - MAX_RULES
    print(f"  [3/5] Split Tunnel 规则总数 {len(rules)} > {MAX_RULES}，已截断尾部 {removed} 条 IP 规则")
    return truncated


# ════════════════════════════════════════════
# 步骤 4：写入 Split Tunnel 策略
# ════════════════════════════════════════════

def update_split_tunnels(routes):
    """
    通过 Cloudflare API 写入 Split Tunnel 策略

    写入的域名规则保留通配符前缀（如 *.jd.com）
    写入的 IP 规则保持原样（如 10.0.0.0/8）

    API 端点: PUT /accounts/{id}/devices/policy/{profile_id}/{mode}
    """
    print(f"  [4/5] 写入 Split Tunnel（{len(routes)} 条路由, Mode: {MODE}）...")

    if PROFILE_ID:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/{PROFILE_ID}/{MODE}")
    else:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/{MODE}")

    resp = requests.put(url, json=routes, headers=HEADERS, timeout=60)

    if resp.status_code in (200, 204):
        print(f"  [OK] Split Tunnel 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"  [FAIL] Split Tunnel 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()


# ════════════════════════════════════════════
# 步骤 5：写入 Fallback Domains 策略
# ════════════════════════════════════════════

def update_fallback_domains(fallback_rules):
    """
    通过 Cloudflare API 写入 Local Domain Fallback 策略

    写入的域名规则已去除通配符（如 jd.com）
    所有域名统一使用 FALLBACK_DNS（223.5.5.5）进行 DNS 解析
    仅包含域名规则，不含 IP 规则

    API 端点: PUT /accounts/{id}/devices/policy/{profile_id}/fallback_domains
    请求体: [{ "domain": "jd.com", "description": "...", "dns_server": "223.5.5.5" }]
    """
    print(f"  [5/5] 写入 Fallback Domains（{len(fallback_rules)} 条, DNS: {FALLBACK_DNS}）...")

    if PROFILE_ID:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/{PROFILE_ID}/fallback_domains")
    else:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
               f"/devices/policy/fallback_domains")

    resp = requests.put(url, json=fallback_rules, headers=HEADERS, timeout=60)

    if resp.status_code in (200, 204):
        print(f"  [OK] Fallback Domains 同步成功！{len(fallback_rules)} 条 | DNS: {FALLBACK_DNS}")
    else:
        print(f"  [FAIL] Fallback Domains 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()


# ════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  脚本 B: GitHub -> Cloudflare 分流策略")
    print("=" * 60)

    # 步骤 1：从 GitHub 读取规则（域名带 *. 通配符）
    rules = fetch_rules_from_github()

    # 步骤 2：处理规则，生成两份独立清单
    #   split_tunnel_rules — 原样保留（带 *. 通配符）
    #   fallback_rules — 去除通配符 + 绑定 DNS 223.5.5.5
    split_tunnel_rules, fallback_rules = process_rules(rules)

    # 步骤 3：对 Split Tunnel 应用规则上限
    routes = truncate_rules(split_tunnel_rules)

    # 步骤 4：写入 Split Tunnel（域名保留 *. 通配符）
    update_split_tunnels(routes)

    # 步骤 5：写入 Fallback Domains（域名去通配符 + DNS 223.5.5.5）
    update_fallback_domains(fallback_rules)

    print("
  脚本 B 执行完毕。")


if __name__ == "__main__":
    main()
