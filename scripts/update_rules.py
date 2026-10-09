import argparse
import configparser
import csv
import io
import ipaddress
import json
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "Loyalsoldier/surge-rules"
PROFILE = ROOT / "safe and high speed- China to overseas.conf"
DIRECT_PATH = ROOT / "rules" / "direct.list"
CLOUD_ROOTS = {"aliyun.com", "jdcloud.com"}
DIRECT_URL = (
    "https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/"
    "main/rules/direct.list"
)


def download(url):
    request = Request(url, headers={"User-Agent": "Shadowrocket-Config"})
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
    for key in ("ipv6", "prefer-ipv6", "dns-direct-system"):
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
    assert len(general["always-real-ip"].split(",")) == 7
    assert sections["MITM"] == ["enable = false"]
    rules = list(csv.reader(sections["Rule"]))
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

    def policy(domain):
        for row in rules:
            kind = row[0]
            if kind == "RULE-SET":
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
    }
    for domain, expected in cases.items():
        actual = policy(domain)
        assert actual == expected, (domain, expected, actual)
    print(json.dumps({
        "result": "PASS - static checks only", "domainCases": len(cases),
        "profileRules": len(rules), "directRules": len(direct),
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
    check_profile(proxy_text)


if __name__ == "__main__":
    main()
