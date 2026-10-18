import argparse
import configparser
import csv
import fnmatch
import io
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "Loyalsoldier/surge-rules"
PROFILE = ROOT / "safe and high speed- China to overseas.conf"
DIRECT_PATH = ROOT / "rules" / "direct.list"
DOMAIN_PATH = ROOT / "rules" / "domestic.txt"
SHARED_ROOTS = {
    "aliyun.com", "jdcloud.com", "aliyuncs.com", "myqcloud.com", "qcloud.com",
    "tencentcloud.com", "myhuaweicloud.com", "huaweicloud.com", "hwclouds.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "cloudflare.net",
}
CLOUD_ROOTS = {"aliyun.com", "jdcloud.com"}
APP_REAL_IP_DOMAINS = (
    "qq.com", "weixin.com", "wechat.com", "gtimg.com", "gtimg.cn",
    "qpic.cn", "qlogo.cn", "taobao.com", "tmall.com", "tbcdn.cn",
    "alicdn.com", "jd.com", "360buyimg.com", "jdpay.com",
    "pinduoduo.com", "yangkeduo.com", "pddpic.com",
)
PAYMENT_DOMAINS = (
    "unionpay.com", "unionpay.net", "unionpaysecure.com", "chinaunionpay.com",
    "95516.com", "95516.net", "chinapay.com", "chinaums.com",
)
DIRECT_URL = (
    "https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/"
    "main/rules/direct.list"
)


def download(url):
    headers = {"User-Agent": "Shadowrocket-Config"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8-sig")


def read_domain_rules(text):
    lines = (
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    rows = []
    for row in csv.reader(lines):
        if len(row) != 2 or row[0] not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            raise ValueError(f"Unsupported domain rule: {row!r}")
        if not row[1] or row[1] != row[1].strip():
            raise ValueError(f"Invalid domain: {row!r}")
        rows.append(tuple(row))
    return rows


def filter_rules(rows):
    return [
        row for row in rows
        if not (
            row[0] == "DOMAIN-SUFFIX"
            and ("." not in row[1] or row[1] in CLOUD_ROOTS)
        )
    ]


def refresh(ref):
    if len(ref) != 40 or any(c not in "0123456789abcdef" for c in ref):
        raise ValueError("Expected an upstream commit SHA")
    source = f"https://raw.githubusercontent.com/{UPSTREAM}/{ref}/ruleset/direct.txt"
    original = read_domain_rules(download(source))
    filtered = filter_rules(original)
    if len(filtered) < 50000:
        raise ValueError("Unexpectedly small upstream list")
    output = io.StringIO(newline="")
    output.write(f"# Modified from {UPSTREAM}; GPL-3.0\n# Source: {source}\n")
    csv.writer(output, lineterminator="\n").writerows(filtered)
    license_path = DIRECT_PATH.parent / "LICENSE"
    license_text = None
    if not license_path.exists():
        license_text = download(
            f"https://raw.githubusercontent.com/{UPSTREAM}/master/LICENSE"
        )
        if "GNU GENERAL PUBLIC LICENSE" not in license_text:
            raise ValueError("Unexpected upstream license")
    DIRECT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if license_text is not None:
        license_path.write_text(license_text, encoding="utf-8", newline="\n")
    DIRECT_PATH.write_text(output.getvalue(), encoding="utf-8", newline="\n")
    print(json.dumps({
        "upstream": ref, "sourceRules": len(original),
        "filteredRules": len(filtered), "removed": len(original) - len(filtered),
    }))


def matches(kind, value, domain):
    if kind == "DOMAIN":
        return domain == value
    if kind == "DOMAIN-SUFFIX":
        return domain == value or domain.endswith("." + value)
    if kind == "DOMAIN-KEYWORD":
        return value in domain
    return False


def domain_text():
    rows = read_domain_rules(DIRECT_PATH.read_text(encoding="utf-8"))
    values = {
        ("+." if kind == "DOMAIN-SUFFIX" else "") + domain
        for kind, domain in rows
        if not (kind == "DOMAIN-SUFFIX" and ("." not in domain or domain in SHARED_ROOTS))
    }
    assert len(values) > 50000
    return "# Derived from direct.list; GPL-3.0\n" + "\n".join(sorted(values)) + "\n"


def check_profile(proxy_text):
    text = PROFILE.read_text(encoding="utf-8")
    sections = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current in sections:
                raise ValueError(f"Duplicate section: {current}")
            sections[current] = []
        elif current is None:
            raise ValueError("Entry outside a section")
        else:
            sections[current].append(line)
    settings = configparser.ConfigParser(interpolation=None)
    settings.read_string(
        "[General]\n" + "\n".join(sections["General"])
        + "\n[Host]\n" + "\n".join(sections["Host"])
    )
    general = settings["General"]
    for key in ("ipv6", "prefer-ipv6", "dns-direct-system", "dns-direct-fallback-proxy"):
        assert general[key] == "false", key
    assert general["always-ip-address"] == "true"
    assert general["udp-policy-not-supported-behaviour"] == "REJECT"
    for key in ("dns-server", "fallback-dns-server"):
        assert all(
            value.startswith("https://") and value.endswith("#proxy")
            for value in general[key].split(",")
        ), key
    for key in ("direct-dns-server", "proxy-dns-server"):
        assert all(value.startswith("https://") for value in general[key].split(",")), key
    assert "system" not in general["fallback-dns-server"]
    domestic_dns = {
        "https://dns.alidns.com/dns-query", "https://doh.pub/dns-query",
    }
    for key in ("direct-dns-server", "proxy-dns-server"):
        assert set(general[key].split(",")) == domestic_dns, key
    foreign_dns_ips = set()
    for key in ("dns-server", "fallback-dns-server"):
        for value in general[key].split(","):
            endpoint = urlsplit(value)
            assert endpoint.scheme == "https" and endpoint.fragment == "proxy", key
            assert endpoint.path == "/dns-query", key
            assert endpoint.hostname in {"1.1.1.1", "8.8.8.8"}, key
            foreign_dns_ips.add(endpoint.hostname)
    real_ip_patterns = general["always-real-ip"].split(",")
    expected_patterns = {
        "localhost", "*.local", "*.lan", "*.home.arpa",
        "captive.apple.com", "time.apple.com", "time-ios.apple.com",
    }
    for domain in APP_REAL_IP_DOMAINS:
        expected_patterns.update((domain, "*." + domain))
    assert len(real_ip_patterns) == len(expected_patterns)
    assert set(real_ip_patterns) == expected_patterns
    assert sections["MITM"] == ["enable = false"]
    rules = list(csv.reader(sections["Rule"]))
    assert rules[:3] == [
        ["DST-PORT", "53", "REJECT"],
        ["DST-PORT", "853", "REJECT"],
        ["IP-CIDR6", "::/0", "REJECT", "no-resolve"],
    ]
    first_remote = next(i for i, row in enumerate(rules) if row[0] == "RULE-SET")
    for hostname in ("dns.alidns.com", "doh.pub"):
        assert rules.index(["DOMAIN", hostname, "DIRECT"]) < first_remote
        for address in settings["Host"][hostname].split(","):
            assert ipaddress.ip_address(address).version == 4
            assert rules.index([
                "IP-CIDR", address + "/32", "DIRECT", "no-resolve",
            ]) < first_remote
    for address in foreign_dns_ips:
        assert rules.index([
            "IP-CIDR", address + "/32", "PROXY", "no-resolve",
        ]) < first_remote
    for domain in PAYMENT_DOMAINS:
        assert rules.index(["DOMAIN-SUFFIX", domain, "DIRECT"]) < first_remote
    direct = read_domain_rules(DIRECT_PATH.read_text(encoding="utf-8"))
    proxy = read_domain_rules(proxy_text)
    assert direct == filter_rules(direct)
    assert len(direct) >= 50000
    assert ["RULE-SET", DIRECT_URL, "DIRECT"] in rules
    assert rules.index(["DOMAIN-KEYWORD", ".", "PROXY"]) < rules.index(
        ["GEOIP", "CN", "DIRECT", "no-resolve"]
    )
    assert rules[-1] == ["FINAL", "PROXY"]
    for row in rules:
        if row[0] in {"IP-CIDR", "IP-CIDR6", "GEOIP"}:
            assert row[-1] == "no-resolve", row
        if row[0] == "IP-CIDR":
            assert not ipaddress.ip_network(row[1]).overlaps(
                ipaddress.ip_network("198.18.0.0/15")
            ), row
    tables = {"proxy.txt": proxy, "direct.list": direct}

    def policy(domain, remote_available=True):
        for row in rules:
            kind = row[0]
            if kind == "RULE-SET":
                if not remote_available:
                    continue
                table = tables.get(row[1].rsplit("/", 1)[-1], ())
                if any(matches(*entry, domain) for entry in table):
                    return row[2]
            elif matches(kind, row[1], domain):
                return row[2]
            elif kind == "FINAL":
                return row[1]
        raise ValueError(f"No route: {domain}")

    cases = {
        "localhost": "DIRECT", "printer.local": "DIRECT",
        "nas.home.arpa": "DIRECT", "dns.alidns.com": "DIRECT",
        "doh.pub": "DIRECT", "captive.apple.com": "DIRECT",
        "time.apple.com": "DIRECT", "mp.weixin.qq.com": "DIRECT",
        "mobile.alipay.com": "DIRECT", "www.icbc.com.cn": "DIRECT",
        "api.amap.com": "DIRECT", "www.bilibili.com": "DIRECT",
        "api.douyin.com": "DIRECT", "www.jd.com": "DIRECT",
        "www.xiaomi.com": "DIRECT", "www.mi.com": "DIRECT",
        "www.aliyun.com": "DIRECT", "www.jdcloud.com": "DIRECT",
        "chatgpt.com": "PROXY", "api.openai.com": "PROXY",
        "www.youtube.com": "PROXY", "api.github.com": "PROXY",
        "web.telegram.org": "PROXY", "www.google.cn": "PROXY",
        "www.alibabacloud.com": "PROXY",
        "unclassified-review-sample.cn": "PROXY",
        "unclassified-review-sample.example": "PROXY",
        "unclassified-review-sample.aliyun.com": "PROXY",
        "unclassified-review-sample.jdcloud.com": "PROXY",
        "user.95516.com": "DIRECT", "wallet.95516.com": "DIRECT",
        "yunshanfu.unionpay.com": "DIRECT", "appcashier.95516.com": "DIRECT",
    }
    for domain in PAYMENT_DOMAINS:
        cases[domain] = "DIRECT"
        cases["api." + domain] = "DIRECT"
        cases[domain + ".unrelated.example"] = "PROXY"
    for domain in APP_REAL_IP_DOMAINS:
        for sample in (domain, "media." + domain):
            cases[sample] = "DIRECT"
            assert any(fnmatch.fnmatchcase(sample, p) for p in real_ip_patterns)
        assert not any(
            fnmatch.fnmatchcase(domain + ".unrelated.example", p)
            for p in real_ip_patterns
        )
    for domain, expected in cases.items():
        actual = policy(domain)
        assert actual == expected, (domain, expected, actual)
        if expected == "PROXY":
            assert not any(
                fnmatch.fnmatchcase(domain, p) for p in real_ip_patterns
            ), domain
    # Model missing tables; native download/compile failures require device testing.
    independent_cases = {
        domain: expected for domain, expected in cases.items()
        if domain not in {"www.xiaomi.com", "www.mi.com"}
    }
    for domain, expected in independent_cases.items():
        assert policy(domain, remote_available=False) == expected, domain
    print(json.dumps({
        "result": "PASS - static checks only", "domainCases": len(cases),
        "profileRules": len(rules), "directRules": len(direct),
        "realIpExceptions": len(real_ip_patterns),
        "withoutRemoteTables": len(independent_cases),
        "clientRuntimeTested": False,
    }))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ref = args.ref
    if ref is None:
        ref = json.loads(download(
            f"https://api.github.com/repos/{UPSTREAM}/commits/release"
        ))["sha"]
    proxy_text = download(
        f"https://raw.githubusercontent.com/{UPSTREAM}/{ref}/ruleset/proxy.txt"
    )
    if not args.check:
        refresh(ref)
        DOMAIN_PATH.write_text(domain_text(), encoding="utf-8", newline="\n")
    else:
        assert DOMAIN_PATH.read_text(encoding="utf-8") == domain_text()
    check_profile(proxy_text)


if __name__ == "__main__":
    main()
