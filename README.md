# Shadowrocket 大陆直连 / 境外代理

适用于中国大陆本地宽带或蜂窝网络。国内服务直连；境外服务经已选节点代理，IPv6 默认关闭。本仓库只提供 Shadowrocket 配置，不含节点或订阅。

```text
国内服务：大陆设备 -> 国内目标
境外服务：大陆设备 -> 大陆中转入口 -> 境外出口 -> 目标服务
```

中转与出口由节点服务商提供，本配置不会创建服务器端链路。

## 导入

[配置直链](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/safe%20and%20high%20speed-%20China%20to%20overseas.conf)

1. 在 Shadowrocket「配置」中添加上述 URL，下载并选中配置。
2. 首页「全局路由」选择「配置」，再选择可用节点。`PROXY` 使用首页已选节点。
3. 更新配置内的三个远程规则集，确认全部下载成功。首次下载失败时，可先用原有可联网配置完成下载。
4. 首轮检查时停用会覆盖 DNS、路由或 HTTPS 解密的模块，以及浏览器自设 DNS、其他 DNS 描述文件。
5. 需要通话或游戏时，确认节点支持并开启 UDP 转发；不支持时会拒绝相应代理 UDP，不回退直连。

## 分流

按顺序首次匹配：DNS / IPv6 防护 -> 局域网与解析器地址 -> 明确的国内外域名 -> 远程代理列表 -> 远程直连列表 -> Telegram IP -> 大陆 IP -> 其余代理。

银行、支付、政务和常用国内 App 域名优先直连；Google、YouTube、GitHub、境外 AI 和常用境外社交通讯域名优先代理。规则按目的域名/IP 匹配，不按 App 包名匹配，共享域名不能区分来自哪个 App。

## DNS 与 IPv6

| 查询用途 | 配置路径 |
| --- | --- |
| 国内直连域名 | 阿里 DNS / DNSPod DoH，直连 |
| 节点域名 | 独立的国内 DoH，用于连接节点 |
| 一般查询与境外代理域名 | Cloudflare DoH，经代理 |
| 备用查询 | Google DoH，经代理 |

- 不配置明文或系统 DNS 回退；境外 DoH 地址带 `#proxy`。国内解析器仍能看到交给它们的域名。
- 开启 `always-ip-address`，让客户端按配置解析后连接；境外首访可能增加解析等待，不承诺所有连接提速。
- 国内 DNS 失败时可能使用境外代理 DoH 备用，业务仍保持 DIRECT，但 CDN 选址和延迟可能受影响。
- 劫持列出的公共 DNS；拒绝进入规则引擎的其余 53 / 853 端口连接及裸 IPv6 连接。强制使用这些端口的 App 可能受影响。
- `ipv6`、`prefer-ipv6` 均关闭；节点自身的 IPv6 解析也须单独检查。这不是关闭 iOS 系统 IPv6。

## 边界

配置不能保证 App 检测不到 VPN，也不能单独证明“零 DNS 泄露”。TUN Only 仍是 VPN；App 自带 HTTPDNS/DoH、系统绕行、共享域名错分和服务商行为需实机核验。国内域名及节点域名使用指定国内 DoH，是本配置允许的解析路径。

VPN 关闭、崩溃或系统重建网络时，本配置不是系统级断网保护。`close-if-proxy-chain-missing` 只保护 Shadowrocket 自身缺失的链条引用，不控制服务商内部中转。本版不包含广告过滤或 HTTPS 解密，也不全局封禁 QUIC / STUN。

## 检查

1. 查看连接记录：国内 App 主要业务应为 DIRECT，境外服务应为 PROXY；检查实际连接，不只看一个出口检测网站。
2. 查看 DNS 记录，并结合网络侧抓包及必要的服务端记录，确认境外测试域名不走本地或系统 DNS。解析器国家和网页出口 IP 不能单独证明无泄露。
3. 分别测试 Wi-Fi、蜂窝和锁屏唤醒，检查 IPv4 业务与节点入口；保持 VPN 开启，改选不可用节点，境外请求应失败而不是直连。
4. 用未缓存的测试域名检查 DNS 失败路径，并测试银行登录、支付、通话和国内视频。

已完成配置静态检查；尚未完成你的 iPhone 导入、实际链路抓包或测速。远程规则会变化，更新失败时应检查缓存和加载状态。

## 参考

- [Shadowrocket App Store](https://apps.apple.com/us/app/shadowrocket/id932747118)：2026-09-29 核对公开版本为 2.2.92；手机安装版本需自行确认。
- [LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket) 与 [lazy.conf](https://github.com/LOWERTOP/Shadowrocket/blob/main/lazy.conf)：社区参数说明，部分内容可能涉及测试版。
- [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)：使用 `release/ruleset/` 中的代理、直连和 Telegram IP 规则。
- [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/)、[Google DoH](https://developers.google.com/speed/public-dns/docs/doh)、[阿里 DNS](https://www.alidns.com/)、[DNSPod 社区接入示例](https://developer.cloud.tencent.com/article/2404099)。
