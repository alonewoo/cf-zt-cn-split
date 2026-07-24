import ipaddress
import requests
import os
import re

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID   = os.getenv("CF_PROFILE_ID", "")
MODE         = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

# ── 配额设置────────────────────────────────────────────────────────────────
MAX_RULES        = 4000   # Cloudflare split tunnel 最多 900 条
MAX_DOMAIN_RULES = 1950   # 域名配额上限

# 合法域名正则
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# ── 域名黑名单关键词 ──────────────────────────────────────────────────────
DOMAIN_BLACKLIST_KEYWORDS = [
    "ddos", "attack", "hack", "exploit", "malware", "virus",
    "trojan", "spam", "phish", "fraud", "scam", "fake",
]

# ── 域名精确黑名单 ────────────────────────────────────────────────────────
DOMAIN_BLACKLIST_EXACT = [
    "aliyunddos0003.com",
    "vjianshen1688.com",
]

# ── 域名白名单品牌校验规则 ────────────────────────────────────────────────
DOMAIN_BRAND_VALIDATION = [
    ("ali", [
        r'^.*\.alibaba\.com$',
        r'^.*\.aliyun\.com$',
        r'^.*\.alicdn\.com$',
        r'^.*\.alipay\.com$',
        r'^.*\.aliexpress\.com$',
        r'^.*\.aliyun-inc\.com$',
        r'^.*\.alibabacloud\.com$',
        r'^.*\.alikunlun\.com$',
        r'^.*\.alimama\.com$',
        r'^.*\.alisoft\.com$',
        r'^.*\.aliimg\.com$',
        r'^.*\.aliapp\.com$',
        r'^.*\.alibaba-inc\.com$',
        r'^.*\.alibabaus\.com$',
    ]),
    ("jd", [
        r'^.*\.jd\.com$',
        r'^.*\.jdcloud\.com$',
        r'^.*\.jingdong\.com$',
        r'^.*\.360buy\.com$',
        r'^.*\.yiyaojd\.com$',
        r'^.*\.jdl\.com$',
        r'^.*\.jdpay\.com$',
        r'^.*\.jdwl\.com$',
        r'^.*\.jdhealth\.com$',
    ]),
    ("1688", [
        r'^.*\.1688\.com$',
        r'^.*\.1688\.net$',
    ]),
    ("tencent|qq|weixin|wechat|wxpay|qcloud", [
        r'^.*\.tencent\.com$',
        r'^.*\.qq\.com$',
        r'^.*\.weixin\.com$',
        r'^.*\.wechat\.com$',
        r'^.*\.qcloud\.com$',
        r'^.*\.gtimg\.com$',
        r'^.*\.qpic\.cn$',
        r'^.*\.qlogo\.cn$',
        r'^.*\.myqcloud\.com$',
        r'^.*\.weiyun\.com$',
    ]),
    ("baidu", [
        r'^.*\.baidu\.com$',
        r'^.*\.baidustatic\.com$',
        r'^.*\.baidupcs\.com$',
        r'^.*\.bdimg\.com$',
        r'^.*\.bdstatic\.com$',
        r'^.*\.bcehost\.com$',
        r'^.*\.bcebos\.com$',
    ]),
    ("bytedance|toutiao|douyin|tiktok", [
        r'^.*\.bytedance\.com$',
        r'^.*\.toutiao\.com$',
        r'^.*\.douyin\.com$',
        r'^.*\.tiktok\.com$',
        r'^.*\.byteimg\.com$',
        r'^.*\.pstatp\.com$',
        r'^.*\.snssdk\.com$',
        r'^.*\.zijieapi\.com$',
    ]),
    ("163", [
        r'^.*\.163\.com$',
        r'^.*\.yun163\.com$',
        r'^.*\.163yun\.com$',
    ]),
    ("10086", [
        r'^.*\.10086\.com$',
        r'^.*\.189\.com$',
        r'^.*\.10010\.com$',
    ]),
]

_compiled_brand_patterns = {}
for keywords_str, patterns in DOMAIN_BRAND_VALIDATION:
    keyword_list = [kw.strip() for kw in keywords_str.split('|')]
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
    for kw in keyword_list:
        if kw not in _compiled_brand_patterns:
            _compiled_brand_patterns[kw] = []
        _compiled_brand_patterns[kw].extend(compiled_patterns)

# ── 域名优先级关键词 ──────────────────────────────────────────────────────
PRIORITY_KEYWORDS: list[list[str]] = [
    # 京东
    ["jd","jingdong", "yiyaojd", "jdcloud", "qianxun", "jdimg", "jdcdn.com", "360buyimg"],
    # 蚂蚁 / 支付宝
    ["alipay", "antgroup", "antfin", "mybank", "smzdm"],
    # 淘宝 / 阿里
    ["taobao", "alibaba", "alicdn", "aliyun", "tmall", "1688.com",
     "amap", "iqiyi", "alipay", "ele.me", "elemecnd.com", "myqcloud.com"],
    # 腾讯
    ["tencent", "qq.com", "weixin", "wechat", "wxpay", "qcloud",
     "weiyun", "myqcloud", "gtimg", "qpic", "qlogo", "v.qq.com"],
    # 三大运营商
    ["cmcc.com", "chinamobile", "10086",                          # 中国移动
     "chinaunicom", "unicom", "10010",    # 中国联通
     "chinatelecom", "189", "ctexm"],       # 中国电信
    # 其他
    ["taikang", "163", "163yun", "cnipa", "baidu", "baidustatic", "baidupcs", "bdimg", "bdstatic",
     "bytedance", "toutiao", "douyin", "tiktok", "byteimg", "pstatp", "snssdk", "zijieapi",
     ],
]

# 域名唯一数据源
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"

# IP 数据源
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

# ── IP 优先级网段 ──────────────────────────────────────────────────────────
PRIORITY_IP_GROUPS: list[tuple[str, list[str]]] = [
    ("国内大厂", [
        "47.52.0.0/14", "47.88.0.0/13", "47.96.0.0/11",
        "106.11.0.0/16", "116.62.0.0/16", "120.55.0.0/16",
        "121.196.0.0/16", "140.205.0.0/16",
        "43.138.0.0/15", "49.234.0.0/16", "101.32.0.0/14",
        "118.24.0.0/16", "119.29.0.0/16", "175.27.0.0/16",
        "203.205.0.0/16",
        "106.12.0.0/16", "180.76.0.0/16", "220.181.0.0/16",
        "101.6.0.0/15", "59.82.0.0/16",
        "119.8.0.0/16", "121.37.0.0/16", "124.70.0.0/15",
        "101.124.0.0/16", "117.147.0.0/16",
        "59.111.0.0/16", "223.252.192.0/18",
        "111.13.0.0/16", "120.92.0.0/16",
        "110.242.68.0/22",
    ]),
    ("三大运营商", [
        "58.16.0.0/12", "61.128.0.0/10", "101.224.0.0/12",
        "113.0.0.0/10", "117.0.0.0/11", "121.0.0.0/11",
        "125.64.0.0/11", "202.96.0.0/11", "218.0.0.0/11",
        "58.240.0.0/12", "61.148.0.0/14", "125.32.0.0/11",
        "218.104.0.0/13", "221.0.0.0/11",
        "117.128.0.0/10", "183.128.0.0/11",
        "211.136.0.0/12", "218.200.0.0/13",
    ]),
]

_PRIORITY_IP_NETS: list[list[ipaddress.IPv4Network]] = []
for _label, _raw_cidrs in PRIORITY_IP_GROUPS:
    _group_nets = []
    for _cidr in _raw_cidrs:
        try:
            _group_nets.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            pass
    _PRIORITY_IP_NETS.append(_group_nets)

# ── 保留规则 ──────────────────────────────────────────────────────────────
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


# ── 域名过滤函数 ──────────────────────────────────────────────────────────

def is_domain_blacklisted(domain: str) -> bool:
    """检查域名是否在黑名单中"""
    domain_lower = domain.lower().lstrip('*.')

    for blacklisted in DOMAIN_BLACKLIST_EXACT:
        blacklisted_lower = blacklisted.lower()
        if domain_lower == blacklisted_lower:
            print(f"   🚫 黑名单精确匹配: {domain} -> 排除")
            return True
        if domain_lower.endswith('.' + blacklisted_lower):
            print(f"   🚫 黑名单后缀匹配: {domain} -> 排除")
            return True
        if blacklisted_lower.endswith('.' + domain_lower):
            print(f"   🚫 黑名单前缀匹配: {domain} -> 排除")
            return True

    for keyword in DOMAIN_BLACKLIST_KEYWORDS:
        keyword_lower = keyword.lower()
        parts = domain_lower.split('.')
        for part in parts:
            if keyword_lower in part and len(part) > len(keyword_lower):
                print(f"   🚫 黑名单关键词({keyword})匹配: {domain} -> 排除")
                return True

    return False


def is_domain_brand_valid(domain: str) -> bool:
    """检查包含品牌关键词的域名是否属于合法品牌域名"""
    domain_lower = domain.lower().lstrip('*.')

    for brand_keyword, patterns in _compiled_brand_patterns.items():
        if brand_keyword in domain_lower:
            for pattern in patterns:
                if pattern.match(domain_lower):
                    return True
            print(f"   🚫 品牌校验失败: {domain} 包含 '{brand_keyword}' 但不匹配已知品牌域名模式 -> 排除")
            return False

    return True


def aggregate_cidrs(cidrs: list[str]) -> list[str]:
    """对 CIDR 列表做最大化聚合"""
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            print(f"   ⚠️  跳过非法 CIDR: {cidr}")
    collapsed = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in collapsed]


def _priority_ip_level(cidr: str) -> int:
    """返回 CIDR 的优先级级别（越小越优先）"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return len(PRIORITY_IP_GROUPS)
    for level, group_nets in enumerate(_PRIORITY_IP_NETS):
        if any(net.overlaps(pn) for pn in group_nets):
            return level
    return len(PRIORITY_IP_GROUPS)


def sort_cidrs_by_priority(cidrs: list[str]) -> list[str]:
    """将 CIDR 列表按大厂/运营商优先排序"""
    return sorted(cidrs, key=_priority_ip_level)


def get_cn_cidrs():
    """从 GeoIP2-CN 拉取 CN CIDR 列表，做最大化聚合，并按大厂/运营商优先排序"""
    print(f"   正在从 {IP_URL} 获取 IP 数据...")
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    raw = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f"   IP 数据源获取到 {len(raw)} 条原始 CIDR")

    aggregated = aggregate_cidrs(raw)
    print(f"   聚合后剩余 {len(aggregated)} 条 CIDR（节省 {len(raw) - len(aggregated)} 条）")

    sorted_cidrs = sort_cidrs_by_priority(aggregated)
    priority_counts = []
    for lvl in range(len(PRIORITY_IP_GROUPS)):
        count = sum(1 for c in sorted_cidrs if _priority_ip_level(c) == lvl)
        priority_counts.append(count)

    labels = [label for label, _ in PRIORITY_IP_GROUPS]
    detail_parts = []
    for i in range(len(labels)):
        detail_parts.append(f"{labels[i]} {priority_counts[i]} 条")
    detail = " | ".join(detail_parts)
    print(f"   IP 优先段：{detail}")
    return sorted_cidrs


def _priority_level(domain: str) -> int:
    """
    返回域名的优先级级别（越小越优先）。
    命中第 0 组关键词 → 返回 0；命中第 1 组 → 返回 1；……未命中 → 返回 len(PRIORITY_KEYWORDS)。
    """
    lower = domain.lower()
    for level, keywords in enumerate(PRIORITY_KEYWORDS):
        if any(kw in lower for kw in keywords):
            return level
    return len(PRIORITY_KEYWORDS)


def sort_domains_by_priority(domains: list[str]) -> list[str]:
    """将域名列表按优先级排序：关键业务域名排在前面"""
    return sorted(domains, key=_priority_level)


def get_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取 CN 域名列表，过滤非法域名，并按优先级排序"""
    print(f"   正在从 {DOMAIN_URL} 获取域名数据...")
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()

    domains = []
    rejected_count = 0
    rejected_reasons = {
        "format": 0,
        "blacklist": 0,
        "brand_fail": 0,
    }

    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        line = line.lstrip('.')

        if not line:
            continue

        domain_with_wildcard = f"*.{line}"
        clean_domain = line

        if VALID_DOMAIN_RE.match(clean_domain):
            if is_domain_blacklisted(line) or is_domain_blacklisted(domain_with_wildcard):
                rejected_count += 1
                rejected_reasons["blacklist"] += 1
                continue
            if not is_domain_brand_valid(line) and not is_domain_brand_valid(domain_with_wildcard):
                rejected_count += 1
                rejected_reasons["brand_fail"] += 1
                continue
            domains.append(domain_with_wildcard)
        else:
            rejected_count += 1
            rejected_reasons["format"] += 1

    unique = list(set(domains))
    sorted_domains = sort_domains_by_priority(unique)
    priority_count = sum(1 for d in sorted_domains if _priority_level(d) < len(PRIORITY_KEYWORDS))

    print(f"   域名数据源获取到 {len(sorted_domains)} 条有效域名")
    print(f"   已过滤 {rejected_count} 条无效/黑名单域名")
    print(f"   过滤详情: 格式非法 {rejected_reasons['format']} | "
          f"黑名单 {rejected_reasons['blacklist']} | "
          f"品牌校验失败 {rejected_reasons['brand_fail']}")
    print(f"   其中优先域名 {priority_count} 条")

    return sorted_domains


def get_priority_domains(domains: list[str]) -> list[str]:
    """从排序后的域名列表中提取优先域名（命中任意优先关键词组的域名）"""
    return [d for d in domains if _priority_level(d) < len(PRIORITY_KEYWORDS)]


def get_priority_ips(cidrs: list[str]) -> list[str]:
    """从排序后的 IP 列表中提取优先 IP（命中大厂或运营商网段的 IP）"""
    return [c for c in cidrs if _priority_ip_level(c) < len(PRIORITY_IP_GROUPS)]


def update_split_tunnels(cidrs, domains):
    """
    更新 Cloudflare Zero Trust split tunnel 规则。
    最终写入仅包含：保留规则 + 优先域名 + 优先 IP
    """
    preserved_count = len(PRESERVED_RULES)

    # 提取优先域名和优先 IP
    priority_domains = get_priority_domains(domains)
    priority_ips = get_priority_ips(cidrs)

    # 配额约束：优先域名 + 优先 IP 不超过剩余配额
    remaining = MAX_RULES - preserved_count
    max_domains = min(MAX_DOMAIN_RULES, remaining, len(priority_domains))
    max_ips = min(remaining - max_domains, len(priority_ips))

    # 构建规则条目
    domain_entries = [{"host": d, "description": "CN Domain"}
                      for d in priority_domains[:max_domains]]
    ip_entries = [{"address": cidr, "description": "CN IP"}
                  for cidr in priority_ips[:max_ips]]

    # 最终路由 = 保留规则 + 优先域名 + 优先 IP
    routes = PRESERVED_RULES + domain_entries + ip_entries

    # 统计信息
    total_domains = len(domains)
    total_ips = len(cidrs)
    non_priority_domains = total_domains - len(priority_domains)
    non_priority_ips = total_ips - len(priority_ips)

    print(f"\n   ── 规则构成 ──")
    print(f"   保留规则：{preserved_count} 条")
    print(f"   优先域名：{len(priority_domains)} 条 → 实际写入 {len(domain_entries)} 条")
    print(f"   优先 IP：{len(priority_ips)} 条 → 实际写入 {len(ip_entries)} 条")
    print(f"   合计写入：{len(routes)} 条")
    print(f"   ── 未写入 ──")
    print(f"   非优先域名：{non_priority_domains} 条（已排除）")
    print(f"   非优先 IP：{non_priority_ips} 条（已排除）")

    if len(routes) > MAX_RULES:
        print(f"⚠️  规则总数超出限制，已截断至 {MAX_RULES} 条")
        routes = routes[:MAX_RULES]

    # 构建 API URL
    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    print(f"\n   API URL: {url}")
    print(f"   准备更新 {len(routes)} 条规则...")

    try:
        resp = requests.put(url, json=routes, headers=HEADERS, timeout=30)
        if resp.status_code in (200, 204):
            print(f"✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
        else:
            content_type = resp.headers.get('content-type', '')
            if 'application/json' in content_type:
                error_msg = resp.json()
            else:
                error_msg = resp.text[:500]
            print(f"❌ 失败 {resp.status_code}: {error_msg}")
            resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求失败: {e}")
        raise


if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    try:
        cidrs = get_cn_cidrs()
        domains = get_cn_domains()
        update_split_tunnels(cidrs, domains)
    except Exception as e:
        print(f"❌ 执行失败: {e}")
        raise
