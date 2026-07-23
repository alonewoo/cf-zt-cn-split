import os
import re
import ipaddress
from collections import OrderedDict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==================== [按你的参数调整] MAX_RULES=900, TARGET_DOMAIN_N=100 ====================
CF_API_TOKEN    = os.getenv("CF_API_TOKEN", "").strip()
ACCOUNT_ID      = os.getenv("CF_ACCOUNT_ID", "").strip()
PROFILE_ID      = os.getenv("CF_PROFILE_ID", "").strip()
MODE            = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP

MAX_RULES       = int(os.getenv("MAX_RULES", "4000"))          # [按你的参数调整]
TARGET_DOMAIN_N = int(os.getenv("TARGET_DOMAIN_N", "1500"))    # [按你的参数调整]
DOMAIN_FULL_COVERAGE = os.getenv("DOMAIN_FULL_COVERAGE", "0").strip() == "1"
DRY_RUN         = os.getenv("DRY_RUN", "0").strip() == "1"
ALLOWED_MODES   = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

# 防止 Token 里误带 Bearer 前缀
if CF_API_TOKEN.lower().startswith("bearer "):
    CF_API_TOKEN = CF_API_TOKEN[7:].strip()

# ==================== [新增] 附图中原有 Split Tunnel 规则 ====================
# 你截图中的默认规则（私网/组播/DHCP 等），exclude 模式下会保留
PRESERVED_ROUTES = [
    {"address": "ff05::/16",            "description": "-"},
    {"address": "ff04::/16",            "description": "-"},
    {"address": "ff03::/16",            "description": "-"},
    {"address": "ff02::/16",            "description": "-"},
    {"address": "ff01::/16",            "description": "-"},
    {"address": "fe80::/10",            "description": "IPv6 Link Local"},
    {"address": "fd00::/8",             "description": "-"},
    {"address": "255.255.255.255/32",   "description": "DHCP Broadcast"},
    {"address": "240.0.0.0/4",          "description": "-"},
    {"address": "224.0.0.0/24",         "description": "-"},
    {"address": "192.168.0.0/16",       "description": "-"},
    {"address": "192.0.0.0/24",         "description": "-"},
    {"address": "172.16.0.0/12",        "description": "-"},
    {"address": "169.254.0.0/16",       "description": "DHCP Unspecified"},
    {"address": "100.64.0.0/10",        "description": "-"},
    {"address": "10.0.0.0/8",           "description": "-"},
]

VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# ==================== [修改] 改用 ipdeny 聚合源 ====================
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"
IP_URL     = "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"


def get_api_url():
    """根据是否指定 PROFILE_ID 返回 API 路径"""
    base = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy"
    return f"{base}/{PROFILE_ID}/{MODE}" if PROFILE_ID else f"{base}/{MODE}"


# [新增] 带重试的 requests.Session
def make_session():
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    })
    return s


session = make_session()


# [新增] IP CIDR 校验 + 聚合
def aggregate_cidrs(raw_list):
    v4, v6, invalid = [], [], 0
    for c in raw_list:
        c = c.strip()
        if not c or c.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            invalid += 1

    collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    # 先按网络地址排序，保证输出稳定
    collapsed.sort(key=lambda n: (n.version, n.network_address))
    return [str(n) for n in collapsed], invalid


def get_cn_cidrs():
    """从 ipdeny 聚合 CN CIDR 列表"""
    r = session.get(IP_URL, timeout=30)
    r.raise_for_status()

    raw = r.text.splitlines()
    cidrs = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # ipdeny 格式: region ip-range
        parts = line.split()
        if len(parts) >= 2:
            ip_range = parts[1]
            try:
                cidrs.append(ip_range)
            except ValueError:
                continue

    cidrs, invalid = aggregate_cidrs(cidrs)
    # 排序逻辑保留
    cidrs.sort(key=lambda c: (ipaddress.ip_network(c).prefixlen, str(c)))
    print(f"   IP 数据源：原始 {len(raw)} 行，提取到 {len(cidrs)} 条，非法/跳过 {invalid} 条")
    return cidrs


def get_cn_domains():
    """从 Loyalsoldier 拉取精选 CN 直连域名，过滤非法格式"""
    r = session.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()

    roots = set()
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 兼容 DOMAIN-SUFFIX,xxx
        if line.startswith("DOMAIN-SUFFIX,"):
            line = line.replace("DOMAIN-SUFFIX,", "", 1).strip()

        line = line.lstrip(".").lower()
        if line and VALID_DOMAIN_RE.match(line):
            roots.add(line)

    print(f"   域名数据源：{len(roots)} 条根域名（已过滤非法格式）")
    return sorted(roots)


# [新增] 域名路由生成（可选同时写入根域名 + 通配符）
def make_domain_routes(roots):
    routes = []
    for d in roots:
        if DOMAIN_FULL_COVERAGE:
            routes.append({"host": d, "description": "CN Domain"})
            routes.append({"host": f"*.{d}", "description": "CN Domain wildcard"})
        else:
            routes.append({"host": f"*.{d}", "description": "CN Domain"})
    return routes


# [新增] 合并并去重，避免新增规则与保留规则重复
def merge_routes(preserved, domains, ips, max_rules):
    routes_map = OrderedDict()
    for entry in preserved + domains + ips:
        key = (entry.get("address"), entry.get("host"))
        routes_map[key] = entry

    routes = list(routes_map.values())
    if len(routes) > max_rules:
        print(f"⚠️  合并去重后共 {len(routes)} 条，超过 {max_rules} 条，已截断")
        routes = routes[:max_rules]
    return routes


def update_split_tunnels(cidrs, domains):
    # [修改] 只在 exclude 模式保留附图中的本地规则；include 模式默认不需要
    preserved = PRESERVED_ROUTES if MODE == "exclude" else []
    print(f"🛡️ 保留默认规则：{len(preserved)} 条")

    # [修改] 先扣掉保留规则配额，再分配给域名/IP
    reserved_count = len(preserved)
    available = max(0, MAX_RULES - reserved_count)

    entries_per_domain = 2 if DOMAIN_FULL_COVERAGE else 1
    max_roots = min(
        TARGET_DOMAIN_N,
        len(domains),
        available // entries_per_domain if entries_per_domain else 0,
    )
    selected_roots = domains[:max_roots]
    domain_routes = make_domain_routes(selected_roots)

    remaining = available - len(domain_routes)
    max_ips = min(remaining, len(cidrs))
    ip_routes = [{"address": cidr, "description": "CN IP"} for cidr in cidrs[:max_ips]]

    routes = merge_routes(preserved, domain_routes, ip_routes, MAX_RULES)

    print(f"   保留 {len(preserved)} | 域名 {len(domain_routes)} | IP {len(ip_routes)} |"
          f" 合计（去重后）{len(routes)} | Mode: {MODE}")

    if DRY_RUN:
        print("🧪 DRY_RUN=1，跳过 Cloudflare API 调用（仅预览上方统计）")
        return

    url = get_api_url()
    resp = session.put(url, json=routes, timeout=60)

    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"❌ 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()


if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    update_split_tunnels(cidrs, domains)
