# Shadowrocket Config

Personal settings with IPv6 disabled by default.

[Download configuration](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/safe%20and%20high%20speed-%20China%20to%20overseas.conf)

## Setup

1. Import the file under Config in Shadowrocket and select it.
2. Set Global Routing to Config and choose a working node.
3. Refresh all three remote rule sets.

## Notes

- Nodes and subscriptions are not included.
- Real-IP exceptions cover local services, QQ, WeChat, Taobao, JD and Pinduoduo.
- Rules use checked snapshots. Update the profile to receive a newer snapshot.
- Shared cloud domains use scoped mainland storage rules.
- Enable UDP on a compatible node when needed.
- Keep the CONNECT test URL unchanged when comparing nodes.
- Check node-level IPv6 settings separately and avoid conflicting DNS or routing overrides.
- Static checks only; verify essential apps on your device.

References: [Shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118), [LOWERTOP](https://github.com/LOWERTOP/Shadowrocket), [Loyalsoldier](https://github.com/Loyalsoldier/surge-rules).

Filtered rules retain the upstream [GPL-3.0 license](rules/LICENSE).

## Local routing

[groups.yaml](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/groups.yaml) replaces groups and rules in a Mihomo subscription. Keep DNS override on. Disable the old profile.js override. Nodes and providers are inherited; no credentials are stored here.

- Groups: PROXY, 自动选择, 故障转移, AI服务, 社媒服务, 银行服务.
- PROXY keeps plan notices. Automatic groups exclude notices and direct/reject nodes.
- WeChat/QQ messaging, media and files use DIRECT. IP-only native-client traffic also uses DIRECT; external websites follow domain rules.
- Listed IBKR/HK/MO/AE banks and mainland banks use 银行服务 (default DIRECT).
- Mainland domains/IPs use DIRECT; other and unknown domains use PROXY. Fake-IP ranges are not bypassed.
- DNS and TUN are not set by this file. Foreign resolver IPs 8.8.8.8 and 1.1.1.1 use 故障转移.
- Imports replace rules, so custom subscription rules need review. Other clients must support Mihomo YAML merging.

For overseas-bank DNS, add this first row in the existing DNS policy editor when enabling this override:

| Policy | Servers |
| --- | --- |
| rule-set:bank-overseas | https://8.8.8.8/dns-query#故障转移,https://1.1.1.1/dns-query#故障转移 |

Keep the existing domestic and foreign DNS policies. Routing alone does not update DNS policy; the bank row requires this override to be enabled. Plan notices remain informational, not recommended node choices. New app endpoints may need additions; no throughput or leak-test result is implied.

Sources: [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat), [HKMA](https://www.hkma.gov.hk/eng/smart-consumers/payment-connect/), [AMCM](https://www.amcm.gov.mo/pt/news-notice/financial-consumption-dispute-settlement-plan/member-list), [UBF](https://ubf.ae/en/customers/member). Bank domains are scoped to listed services; shared bank domains can cover more than one region.

## Service groups

[services.yaml](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/services.yaml) refines the matching subscription into 24 groups. Bind it only to that profile in Clash Party; it inherits the original rule providers and current nodes. Use it separately from groups.yaml and profile.js.

GPT and Claude are separate. X includes Grok; META includes Meta AI; Muse (muse.ai) has its own group; Google includes Gemini, AI Studio and NotebookLM; Microsoft includes Copilot and GitHub Copilot. Dedicated AI rules precede broad categories. Other service groups remain. DNS and TUN are not changed.

Inline service rules are a 2026-10-16 snapshot from [v2fly](https://github.com/v2fly/domain-list-community), under the [MIT license](rules/SERVICES-LICENSE). Refresh this file for future domain additions.
