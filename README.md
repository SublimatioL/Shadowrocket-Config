# Shadowrocket Config

Personal settings with IPv6 disabled by default.

[Download configuration](https://raw.githubusercontent.com/SublimatioL/Shadowrocket-Config/main/safe%20and%20high%20speed-%20China%20to%20overseas.conf)

## Setup

1. Import the file under Config in Shadowrocket and select it.
2. Set Global Routing to Config and choose a working node.
3. Refresh all three remote rule sets.

## Notes

- Nodes and subscriptions are not included.
- Fake-IP uses limited local, time-sync and connectivity-check exceptions.
- Domestic rules are filtered and refreshed daily.
- Enable UDP on a compatible node when needed.
- Keep the CONNECT test URL unchanged when comparing nodes.
- Check node-level IPv6 settings separately and avoid conflicting DNS or routing overrides.
- Static checks only; verify essential apps on your device.

References: [Shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118), [LOWERTOP](https://github.com/LOWERTOP/Shadowrocket), [Loyalsoldier](https://github.com/Loyalsoldier/surge-rules).

Filtered rules retain the upstream [GPL-3.0 license](rules/LICENSE).
