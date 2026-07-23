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
MAX_DOMAIN_RULES = 1550   # 域名配额上限（即"域名优先充满，剩余空间才给 IP"）

# 合法域名正则：只保留标准域名格式，过滤脏数据
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# ── 域名优先级关键词（配额不足时，包含这些关键词的域名优先保留）────────────
# 按重要性分组，同组内关键词等价；分组顺序决定优先级高低
PRIORITY_KEYWORDS: list[list[str]] = [
    # 京东
    ["jd.com", "jingdong", "360buy", "yiyaojd", "jdcloud"],
    # 蚂蚁 / 支付宝
    ["alipay", "antgroup", "antfin", "mybank", "zmxy"],
    # 淘宝 / 阿里
    ["taobao", "alibaba", "alicdn", "aliyun", "tmall", "1688",
     "amap", "dingtalk", "youku", "iqiyi", "alipay"],
    # 腾讯
    ["tencent", "qq", "weixin", "wechat", "wxpay", "qcloud",
     "weiyun", "myqcloud", "gtimg", "qpic", "qlogo"],
    # 三大运营商
    ["cmcc", "chinamobile", "10086",                          # 中国移动
     "chinaunicom", "unicom", "10010", "wostore", "wlan",    # 中国联通
     "chinatelecom", "189", "21cn", "ctexm"],       # 中国电信
]

# 域名唯一数据源：Loyalsoldier 精选直连域名
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"

# IP 唯一数据源：GeoIP2-CN
# IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

# 备用 IP 数据源（仅供参考，不启用）
# IPdeny aggregated (~2200 条):
IP_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
# metowolf/iplist (~1700 条):
#   https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt


# ── IP 优先级网段（配额不足时，大厂/运营商地址段优先保留）─────────────────
# 使用 overlaps() 判断聚合后的 CIDR 是否命中；按重要性分组，组序决定优先级
# 数据来源：APNIC/CNNIC 公开 ASN 分配记录
PRIORITY_IP_GROUPS: list[tuple[str, list[str]]] = [
    ("国内大厂", [
        # 阿里巴巴 / 阿里云 (ASN 37963, 45102, 134963)
        "47.52.0.0/14", "47.88.0.0/13", "47.96.0.0/11",
        "106.11.0.0/16", "116.62.0.0/16", "120.55.0.0/16",
        "121.196.0.0/16", "140.205.0.0/16",
        # 腾讯 / 腾讯云 (ASN 45090, 132203)
        "43.138.0.0/15", "49.234.0.0/16", "101.32.0.0/14",
        "118.24.0.0/16", "119.29.0.0/16", "175.27.0.0/16",
        "203.205.0.0/16",
        # 百度 (ASN 38365, 55967)
        "106.12.0.0/16", "180.76.0.0/16", "220.181.0.0/16",
        # 字节跳动 / 抖音 (ASN 138699, 55960)
        "101.6.0.0/15", "59.82.0.0/16",
        # 华为云 (ASN 55990)
        "119.8.0.0/16", "121.37.0.0/16", "124.70.0.0/15",
        # 京东云 (ASN 138915)
        "101.124.0.0/16", "117.147.0.0/16",
        # 网易 (ASN 4538)
        "59.111.0.0/16", "223.252.192.0/18",
        # 小米 (ASN 38473)
        "111.13.0.0/16", "120.92.0.0/16",
        # 美团 (ASN 138151)
        "110.242.68.0/22",
    ]),
    ("三大运营商", [
        # 中国电信 (ASN 4134, 4812)
        "58.16.0.0/12", "61.128.0.0/10", "101.224.0.0/12",
        "113.0.0.0/10", "117.0.0.0/11", "121.0.0.0/11",
        "125.64.0.0/11", "202.96.0.0/11", "218.0.0.0/11",
        # 中国联通 (ASN 4837, 17816)
        "58.240.0.0/12", "61.148.0.0/14", "125.32.0.0/11",
        "218.104.0.0/13", "221.0.0.0/11",
        # 中国移动 (ASN 9808, 56040)
        "117.128.0.0/10", "183.128.0.0/11",
        "211.136.0.0/12", "218.200.0.0/13",
    ]),
]

# 模块加载时预编译优先级网络对象，避免在排序时重复解析
_PRIORITY_IP_NETS: list[list[ipaddress.IPv4Network]] = []
for _label, _raw_cidrs in PRIORITY_IP_GROUPS:
    _group_nets = []
    for _cidr in _raw_cidrs:
        try:
            _group_nets.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            pass
    _PRIORITY_IP_NETS.append(_group_nets)


# ── 需要始终保留的原始 split tunnel 规则（来自 Cloudflare 控制台截图）──────
# 这些是私有地址、链路本地、多播及 DHCP 相关地址，必须保留以确保本地网络正常
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


def aggregate_cidrs(cidrs: list[str]) -> list[str]:
    """
    对 CIDR 列表做最大化聚合（合并相邻/重叠网段），返回聚合后的字符串列表。
    使用 Python 标准库 ipaddress.collapse_addresses()，无需额外依赖。
    """
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            print(f"   ⚠️  跳过非法 CIDR: {cidr}")
    collapsed = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in collapsed]


def _priority_ip_level(cidr: str) -> int:
    """
    返回 CIDR 的优先级级别（越小越优先）。
    与第 0 组（大厂）任意网段 overlaps → 返回 0；第 1 组（运营商）→ 返回 1；未命中 → 返回 len(PRIORITY_IP_GROUPS)。
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return len(PRIORITY_IP_GROUPS)
    for level, group_nets in enumerate(_PRIORITY_IP_NETS):
        if any(net.overlaps(pn) for pn in group_nets):
            return level
    return len(PRIORITY_IP_GROUPS)


def sort_cidrs_by_priority(cidrs: list[str]) -> list[str]:
    """将 CIDR 列表按大厂/运营商优先排序，配额不足时确保关键网段不被丢弃"""
    return sorted(cidrs, key=_priority_ip_level)


def get_cn_cidrs():
    """从 GeoIP2-CN 拉取 CN CIDR 列表，做最大化聚合，并按大厂/运营商优先排序"""
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    raw = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f"   IP 数据源获取到 {len(raw)} 条原始 CIDR")

    aggregated = aggregate_cidrs(raw)
    print(f"   聚合后剩余 {len(aggregated)} 条 CIDR（节省 {len(raw) - len(aggregated)} 条）")

    sorted_cidrs = sort_cidrs_by_priority(aggregated)
    priority_counts = [
        sum(1 for c in sorted_cidrs if _priority_ip_level(c) == lvl)
        for lvl in range(len(PRIORITY_IP_GROUPS))
    ]
    labels = [label for label, _ in PRIORITY_IP_GROUPS]
    detail = " | ".join(f"{labels[i]} {priority_counts[i]} 条" for i in range(len(labels)))
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
    """将域名列表按优先级排序：关键业务域名排在前面，其余随机跟随"""
    return sorted(domains, key=_priority_level)


def get_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取精选 CN 直连域名列表，过滤非法格式，并按优先级排序"""
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 兼容 DOMAIN-SUFFIX,xxx 格式
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        # 去掉前导点（如 .baidu.com → baidu.com）
        line = line.lstrip('.')
        # 只保留合法域名格式，过滤脏数据
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f"*.{line}")
    unique = list(set(domains))

    # 按优先级排序：关键业务域名（京东/蚂蚁/支付宝/淘宝/腾讯）排在最前
    sorted_domains = sort_domains_by_priority(unique)
    priority_count = sum(1 for d in sorted_domains if _priority_level(d) < len(PRIORITY_KEYWORDS))
    print(f"   域名数据源获取到 {len(sorted_domains)} 条域名（已过滤非法格式，其中优先域名 {priority_count} 条）")
    return sorted_domains


def update_split_tunnels(cidrs, domains):
    # 保留规则占用的配额
    preserved_count = len(PRESERVED_RULES)
    remaining       = MAX_RULES - preserved_count    # 可供 CN 规则使用的配额

    # 域名优先于 IP：先用尽域名配额（最多 MAX_DOMAIN_RULES 条），剩余才给 IP
    max_domains = min(MAX_DOMAIN_RULES, remaining, len(domains))
    max_ips     = min(remaining - max_domains, len(cidrs))

    # 域名规则在前（DNS 层优先命中），IP 规则在后（网络层兜底）
    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]

    # 最终路由 = 保留规则 + CN 域名 + CN IP
    routes = PRESERVED_RULES + domain_entries + ip_entries

    domain_priority_count = sum(1 for e in domain_entries if _priority_level(e["host"]) < len(PRIORITY_KEYWORDS))
    ip_priority_count     = sum(1 for e in ip_entries if _priority_ip_level(e["address"]) < len(PRIORITY_IP_GROUPS))
    print(
        f"   保留规则：{preserved_count} 条"
        f" | 域名：{len(domain_entries)} 条（优先 {domain_priority_count} 条）"
        f" | IP：{len(ip_entries)} 条（优先 {ip_priority_count} 条）"
        f" | 合计：{len(routes)} 条"
    )

    if len(routes) > MAX_RULES:
        print(f"⚠️  规则总数超出限制，已截断至 {MAX_RULES} 条")
        routes = routes[:MAX_RULES]

    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    resp = requests.put(url, json=routes, headers=HEADERS)
    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"❌ 失败 {resp.status_code}: Cloudflare API 请求未成功")
        resp.raise_for_status()


if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    update_split_tunnels(cidrs, domains)
