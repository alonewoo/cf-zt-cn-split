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
# ── 限额：Cloudflare split tunnel 最多 900 条 ──────────────────────────────
MAX_RULES       = 900
TARGET_DOMAIN_N = 100  # 期望域名条数，剩余配额给 IP
# 合法域名正则：只保留标准域名格式，过滤脏数据
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
# 域名：Loyalsoldier 精选直连域名
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"
# IP：GeoIP2-CN
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"
# 备用 IP 数据源
# IPdeny aggregated (~2200 条):
#   https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
# metowolf/iplist (~1700 条):
#   https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt
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
def get_cn_cidrs():
    """从 GeoIP2-CN 拉取 CN CIDR 列表，并做最大化聚合"""
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    raw = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f"   IP 数据源获取到 {len(raw)} 条原始 CIDR")
    aggregated = aggregate_cidrs(raw)
    print(f"   聚合后剩余 {len(aggregated)} 条 CIDR（节省 {len(raw) - len(aggregated)} 条）")
    return aggregated
def get_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取精选 CN 直连域名列表，过滤非法格式"""
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
    print(f"   域名数据源获取到 {len(unique)} 条域名（已过滤非法格式）")
    return unique
def update_split_tunnels(cidrs, domains):
    # 保留规则占用的配额
    preserved_count = len(PRESERVED_RULES)
    remaining       = MAX_RULES - preserved_count          # 可供 CN 规则使用的配额
    # 动态分配配额：域名取 TARGET_DOMAIN_N 条，剩余给 IP
    max_domains = min(TARGET_DOMAIN_N, len(domains), remaining)
    max_ips     = min(remaining - max_domains, len(cidrs))
    # 域名规则在前（DNS 层优先命中），IP 规则在后（网络层兜底）
    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]
    # 最终路由 = 保留规则 + CN 域名 + CN IP
    routes = PRESERVED_RULES + domain_entries + ip_entries
    print(f"   保留规则：{preserved_count} 条 | 域名规则：{len(domain_entries)} 条 | IP 规则：{len(ip_entries)} 条 | 合计：{len(routes)} 条")
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
