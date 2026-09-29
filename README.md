# Shadowrocket: Mainland Direct / Overseas Proxy

For devices using broadband or cellular networks in mainland China. Mainland services connect directly; overseas services use the selected proxy node. IPv6 is disabled by default. This repository provides a Shadowrocket configuration only, without nodes or subscriptions.

```text
Mainland services: mainland device -> mainland destination
Overseas services: mainland device -> mainland relay -> overseas exit -> destination
```

The node provider supplies the relay and overseas exit. This configuration does not create the server-side chain.

## Import

[Configuration URL](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/safe%20and%20high%20speed-%20China%20to%20overseas.conf)

1. Add the URL under Config in Shadowrocket, download the configuration, and select it.
2. Set Global Routing to Config on the home screen, then select a working node. `PROXY` uses the node selected there.
3. Update all three remote rule sets and confirm that each download succeeds. If the initial download fails, use an existing working configuration to download them first.
4. During initial checks, disable modules that override DNS, routing, or HTTPS decryption, along with custom browser DNS and other DNS profiles.
5. For calls or gaming, confirm that the node supports UDP and has UDP forwarding enabled. Unsupported proxy UDP traffic is rejected, without falling back to a direct connection.

## Routing

The first matching rule wins: DNS / IPv6 guards -> LAN and resolver addresses -> explicit mainland and overseas domains -> remote proxy list -> remote direct list -> Telegram IPs -> mainland IPs -> proxy fallback.

Mainland banking, payment, government, and common app domains have direct-connection rules. Google, YouTube, GitHub, overseas AI services, and common overseas social and messaging domains have proxy rules. Matching uses destination domains/IPs, not app package names; shared domains cannot identify the originating app.

## DNS and IPv6

| Query type | Configured path |
| --- | --- |
| Mainland direct domains | AliDNS / DNSPod DoH, direct |
| Node hostnames | Separate mainland DoH for connecting to the node |
| General queries and overseas proxy domains | Cloudflare DoH, through the proxy |
| Fallback queries | Google DoH, through the proxy |

- No plaintext or system DNS fallback is configured. Overseas DoH endpoints use `#proxy`. Mainland resolvers can still see the domains sent to them.
- `always-ip-address` makes the client resolve domains through the configured paths before connecting. Initial overseas requests may take longer to resolve; this does not promise faster connections in every case.
- If mainland DNS fails, fallback queries may use overseas DoH through the proxy. Service traffic remains DIRECT, but CDN selection and latency may change.
- Listed public DNS servers are intercepted. Other connections to ports 53 / 853 and literal IPv6 connections that reach the rule engine are rejected. Apps that require these paths may be affected.
- Both `ipv6` and `prefer-ipv6` are disabled. Check the node's own IPv6 resolution settings separately. This does not disable IPv6 system-wide on iOS.

## Limitations

This configuration cannot guarantee that apps will not detect the VPN, nor can it prove zero DNS leakage on its own. TUN Only is still a VPN. App-specific HTTPDNS/DoH, system bypasses, shared-domain misclassification, and provider behavior require testing on the device. Using the specified mainland DoH resolvers for mainland domains and node hostnames is an allowed DNS path in this configuration.

This configuration is not a system-wide kill switch when the VPN is disabled, crashes, or the system rebuilds network connections. `close-if-proxy-chain-missing` only handles missing references in Shadowrocket's own proxy chains; it does not control the provider's internal relay. This version does not include ad blocking or HTTPS decryption, and does not globally block QUIC / STUN.

## Verification

1. Review connection logs: primary mainland app traffic should use DIRECT, and overseas services should use PROXY. Inspect actual connections, not just one exit-IP test website.
2. Review DNS logs together with network packet captures and, where needed, server logs to confirm that overseas test domains do not use local or system DNS. Resolver country and website exit IP alone cannot prove the absence of leaks.
3. Test Wi-Fi, cellular, and wake-from-lock behavior. Check IPv4 service traffic and the node entry connection. With the VPN still enabled, select an unavailable node: overseas requests should fail rather than connect directly.
4. Use uncached test domains to check DNS failure paths, and test banking login, payments, calls, and mainland video services.

Static configuration checks have been completed. Import testing on your iPhone, packet captures on the actual connection, and speed tests remain outstanding. Remote rules can change; check their cache and loading status if updates fail.

## References

- [Shadowrocket App Store](https://apps.apple.com/us/app/shadowrocket/id932747118): the public version was checked as 2.2.92 on 2026-09-29. Confirm the version installed on your device.
- [LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket) and [lazy.conf](https://github.com/LOWERTOP/Shadowrocket/blob/main/lazy.conf): community parameter documentation; some content may cover beta versions.
- [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules): proxy, direct, and Telegram IP rules from `release/ruleset/`.
- [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/), [Google DoH](https://developers.google.com/speed/public-dns/docs/doh), [AliDNS](https://www.alidns.com/), and the [DNSPod community setup example](https://developer.cloud.tencent.com/article/2404099).
