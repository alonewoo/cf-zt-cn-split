#!/usr/bin/env python3
"""
脚本 A：生成 Cloudflare 分流规则并保存到 GitHub 仓库的 cf_spilit_channel.txt 文件中

规则拼接顺序：
  1. 保留规则（PRESERVED_RULES）
  2. 域名清单 b（经根域校验后的大厂域名）
  3. IP 清单（大厂及三大运营商 ASN 前缀）

环境变量：
  GITHUB_TOKEN   - GitHub Personal Access Token（需 repo 权限）
  GITHUB_REPO    - 仓库地址，格式 owner/repo
  GITHUB_BRANCH  - 目标分支，默认 main

数据来源：
  域名 → Loyalsoldier/surge-rules  direct.txt
  IP   → RIPEstat Data API（按 ASN 查询广播前缀）
         （bgpview.io 已于 2025-11-26 永久关闭，改用 RIPEstat）
"""

import requests
import json
import base64
import os
import re
import time
import ipaddress
from datetime import datetime, timezone

# ════════════════════════════════════════════
# 配置区
# ════════════════════════════════════════════

GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO    = os.getenv("GITHUB_REPO", "")        # owner/repo
GITHUB_BRANCH  = os.getenv("GITHUB_BRANCH", "main")
GITHUB_FILE_PATH = "cf_spilit_channel.txt"

DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"
RIPESTAT_BASE = "https://stat.ripe.net/data/announced-prefixes/data.json"

TIMEOUT = 30

# ── 保留规则 ──
PRESERVED_RULES = [
    {"address": "ff05::/16",            "description": ""},
    {"address": "ff04::/16",            "description": ""},
    {"address": "ff03::/16",            "description": ""},
    {"address": "ff02::/16",            "description": ""},
    {"address": "ff01::/16",            "description": ""},
    {"address": "fe80::/10",            "description": "IPv6 Link Local"},
    {"address": "fd00::/8",             "description": ""},
    {"address": "255.255.255.255/32",   "description": "DHCP Broadcast"},
    {"address": "240.0.0.0/4",          "description": ""},
    {"address": "224.0.0.0/24",         "description": ""},
    {"address": "192.168.0.0/16",       "description": ""},
    {"address": "172.16.0.0/12",        "description": ""},
    {"address": "169.254.0.0/16",       "description": "DHCP Unspecified"},
    {"address": "100.64.0.0/10",        "description": ""},
    {"address": "10.0.0.0/8",           "description": ""},
]

# ── 大厂及运营商域名根域表（用于 list b 校验）──
# 仅当域名精确等于根域，或以 .root 结尾时才视为有效
COMPANY_ROOT_DOMAINS = {
    "京东": [
        "jd.com", "jd.hk", "jd.co", "jingdong.com",
        "360buy.com", "360buyimg.com", "jdcloud.com",
        "jcloud.com", "jdpay.com", "jingxi.com",
        "paipai.com", "jddglobal.com", "jdcloudcs.com",
    ],
    "蚂蚁/支付宝": [
        # Alibaba 生态（蚂蚁/支付宝/阿里云/淘宝系）
        "alibaba.com", "alicdn.com", "aliyun.com", "aliyuncs.com",
        "alibabacloud.com", "taobao.com", "taobao.org",
        "tmall.com", "tmall.hk", "1688.com",
        "alipay.com", "alipay.cn", "alipayobjects.com",
        "antgroup.com", "ant-fin.com", "mybank.cn",
        "antchain.net", "alikatech.com",
        "amap.com", "autonavi.com", "dingtalk.com",
        "fliggy.com", "alitrip.com", "etao.com",
        "aliyunddos.com",   # 不含 aliyunddos0003 等变体
    ],
    "腾讯": [
        "tencent.com", "qq.com", "qcloud.com", "weixin.com",
        "wechat.com", "tencentmusic.com", "gtimg.com",
        "qpic.cn", "qlogo.cn", "idqqimg.com",
        "dnsv1.com", "dnsv3.com", "dnspod.cn",
        "tencentcloudapi.com", "myqcloud.com",
        "tencent-cloud.cn", "tencdns.net", "tencdns.com",
        "tencentcloud.com", "qpic.com", "tencentyun.com",
        "tcdnns.com", "qcloudtest.com",
    ],
    "网易": [
        "netease.com", "163.com", "126.com", "127.com",
        "126.net", "163.net", "neteaseim.com", "yunxin.com",
        "youdao.com", "163mail.com", "163mail.net",
        "neteaseinc.com", "neteasecdn.com",
    ],
    "字节跳动": [
        "bytedance.com", "bytedns.com", "bytedance.net",
        "douyin.com", "douyinpic.com", "douyincdn.com",
        "douyinvod.com", "douyinstatic.com",
        "toutiao.com", "toutiaoimg.com", "toutiaocloud.com",
        "feishu.cn", "larksuite.com",
        "volcengine.com", "volces.com", "bytedance.org",
        "pstatp.com", "snssdk.com", "bytecdntp.com",
        "bytednsdoc.com",
    ],
    "中国电信": [
        "chinatelecom.cn", "189.cn", "21cn.com",
        "ctexcel.com", "chinatelecom.com.cn",
        "21cn.net", "ctcdn.com",
    ],
    "中国联通": [
        "chinaunicom.cn", "10010.com", "unicom.cn",
        "chinaunicom.com", "wo.cn", "unicomcdn.com",
    ],
    "中国移动": [
        "chinamobile.cn", "10086.cn", "chinamobile.com",
        "10086.com", "cmcc.com", "miguvideo.com", "migu.cn",
    ],
}

# ── 大厂及运营商 ASN 列表 ──
COMPANY_ASNS = {
    "阿里云":      [37963, 45102],
    "腾讯云":      [45090, 133478, 132203],
    "京东云":      [55966, 136800],
    "字节跳动":    [396986, 138699],
    "网易":        [45062],
    "中国电信":    [4134, 4809, 4811, 4812, 4813, 4816, 4835, 23724, 4847, 58543],
    "中国联通":    [4837, 10099, 9929, 4808, 17621, 17622, 17623, 17816],
    "中国移动":    [9808, 58453, 56040, 56044, 56045, 56046, 56047, 56048, 24400],
}

# ── 域名关键词（用于 list a 宽泛匹配）──
COMPANY_KEYWORDS = {
    "京东":        ["jd", "jingdong", "360buy", "jdcloud", "jcloud", "paipai", "jingxi"],
    "蚂蚁/支付宝": ["alipay", "ant", "alibaba", "aliyun", "taobao", "tmall",
                   "alicdn", "1688", "dingtalk", "amap", "autonavi", "fliggy"],
    "腾讯":        ["tencent", "qq", "weixin", "wechat", "qcloud", "gtimg",
                   "qpic", "qlogo", "dnspod", "tencentmusic"],
    "网易":        ["netease", "163", "126", "youdao"],
    "字节跳动":     ["bytedance", "douyin", "toutiao", "feishu", "volcengine",
                   "pstatp", "snssdk", "lark"],
    "运营商":      ["chinaunicom", "chinatelecom", "chinamobile", "10010",
                   "10086", "189", "unicom", "cmcc"],
}

VALID_DOMAIN_RE = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# 是否打印被剔除的域名（调试用）
VERBOSE = os.getenv("VERBOSE", "0") == "1"


# ════════════════════════════════════════════
# 数据获取
# ════════════════════════════════════════════

def fetch_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取 CN 直连域名列表"""
    print("  [1/4] 拉取域名数据源 (Loyalsoldier)...")
    r = requests.get(DOMAIN_URL, timeout=TIMEOUT)
    r.raise_for_status()

    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        elif line.startswith('DOMAIN,'):
            line = line.replace('DOMAIN,', '').strip()
        line = line.lstrip('.')
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(line.lower())

    unique = list(set(domains))
    print(f"        数据源获取到 {len(unique)} 条域名")
    return unique


def fetch_asn_prefixes():
    """
    通过 RIPEstat Data API 获取各 ASN 的 IPv4 广播前缀
    API 端点: /data/announced-prefixes/data.json?resource=AS{asn}
    """
    print("  [4/4] 拉取 ASN IP 前缀 (RIPEstat)...")
    ip_entries = []
    seen = set()

    for company, asns in COMPANY_ASNS.items():
        for asn in asns:
            url = f"{RIPESTAT_BASE}?resource=AS{asn}"
            try:
                r = requests.get(url, timeout=TIMEOUT)
                r.raise_for_status()
                data = r.json()
                prefixes = data.get("data", {}).get("prefixes", [])

                count = 0
                for item in prefixes:
                    prefix = item.get("prefix", "")
                    if not prefix or prefix in seen:
                        continue

                    # 仅保留 IPv4 前缀（IPv6 前缀数量过大，保留规则已覆盖关键 IPv6 段）
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                        if net.version != 4:
                            continue
                    except ValueError:
                        continue

                    seen.add(prefix)
                    ip_entries.append({
                        "address": prefix,
                        "description": f"{company} IP"
                    })
                    count += 1

                print(f"        AS{asn} ({company}): {count} 条 IPv4 前缀")
            except Exception as e:
                print(f"        AS{asn} ({company}): 获取失败 - {e}")

            time.sleep(0.5)  # RIPEstat 速率控制

    print(f"        IP 清单合计: {len(ip_entries)} 条（已去重）")
    if len(ip_entries) + len(PRESERVED_RULES) > 4000:
        print(f"  ⚠  IP 前缀数量较多，脚本 B 写入 Cloudflare 时将截断至 4000 条")
    return ip_entries


# ════════════════════════════════════════════
# 域名过滤
# ════════════════════════════════════════════

def filter_domains_phase_a(domains):
    """
    宽泛关键词匹配 → 域名清单 a
    从获取的域名中筛选包含大厂关键词的域名（含 CDN）
    """
    print("  [2/4] 关键词匹配 → 域名清单 a...")
    result = []
    for d in domains:
        dl = d.lower()
        for company, keywords in COMPANY_KEYWORDS.items():
            for kw in keywords:
                if kw in dl:
                    result.append(d)
                    break
            else:
                continue
            break

    unique_a = list(set(result))
    print(f"        清单 a: {len(unique_a)} 条（含误匹配）")
    return unique_a


def validate_domains_phase_b(domains_a):
    """
    根域校验 → 域名清单 b
    剔除 "似是而非" 的域名（如 aliyunddos0003、vjianshen1688.com）
    仅保留精确匹配已知根域、或为已知根域子域的条目
    """
    print("  [3/4] 根域校验 → 域名清单 b...")

    all_roots = set()
    company_of = {}
    for company, roots in COMPANY_ROOT_DOMAINS.items():
        for root in roots:
            all_roots.add(root)
            company_of[root] = company

    result = []
    rejected = []
    for d in domains_a:
        matched = False
        for root in all_roots:
            if d == root or d.endswith('.' + root):
                company = company_of[root]
                result.append({
                    "host": f"*.{d}",
                    "description": f"{company} Domain"
                })
                matched = True
                break
        if not matched:
            rejected.append(d)

    # 去重
    seen_hosts = set()
    unique_b = []
    for entry in result:
        if entry["host"] not in seen_hosts:
            seen_hosts.add(entry["host"])
            unique_b.append(entry)

    print(f"        清单 b: {len(unique_b)} 条（已剔除 {len(rejected)} 条误匹配）")
    if VERBOSE and rejected:
        print("        --- 被剔除的域名 ---")
        for d in sorted(rejected):
            print(f"          ✗ {d}")
    return unique_b


# ════════════════════════════════════════════
# GitHub 上传
# ════════════════════════════════════════════

def save_to_github(content):
    """将规则 JSON 保存到 GitHub 仓库 cf_spilit_channel.txt"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print("  ⚠  未配置 GITHUB_TOKEN / GITHUB_REPO，保存到本地文件")
        local_path = "cf_spilit_channel.txt"
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✅ 已保存到本地: {local_path}")
        return

    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    # 获取现有文件 SHA（用于更新）
    sha = None
    try:
        resp = requests.get(api_url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            sha = resp.json().get("sha")
    except Exception:
        pass

    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    body = {
        "message": f"Auto-update cf_spilit_channel.txt @ {now_str}",
        "content": encoded,
        "branch": GITHUB_BRANCH,
    }
    if sha:
        body["sha"] = sha

    resp = requests.put(api_url, json=body, headers=headers, timeout=TIMEOUT)
    if resp.status_code in (200, 201):
        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_FILE_PATH}"
        print(f"  ✅ 已上传到 GitHub: {raw_url}")
    else:
        print(f"  ❌ GitHub 上传失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()


# ════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  脚本 A: 生成 Cloudflare 分流规则 → GitHub")
    print("=" * 60)

    # 1. 拉取域名数据源
    all_domains = fetch_cn_domains()

    # 2. 关键词匹配 → 域名清单 a
    domains_a = filter_domains_phase_a(all_domains)

    # 3. 根域校验 → 域名清单 b
    domains_b = validate_domains_phase_b(domains_a)

    # 4. 拉取 ASN IP 前缀
    ip_entries = fetch_asn_prefixes()

    # 5. 拼接最终规则: 保留规则 + 域名清单 b + IP 清单
    print("\n  拼接最终规则...")
    final_rules = PRESERVED_RULES + domains_b + ip_entries
    print(f"  保留规则:  {len(PRESERVED_RULES):>6} 条")
    print(f"  域名规则:  {len(domains_b):>6} 条")
    print(f"  IP 规则:   {len(ip_entries):>6} 条")
    print(f"  ────────────────────────")
    print(f"  合计:      {len(final_rules):>6} 条")

    # 6. 保存到 GitHub
    content = json.dumps(final_rules, ensure_ascii=False, indent=2)
    save_to_github(content)

    print("\n  脚本 A 执行完毕。")


if __name__ == "__main__":
    main()
