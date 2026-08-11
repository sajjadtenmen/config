# Free proxy subscriptions

Ready-to-use proxy subscriptions collected from public sources, cleaned of
duplicates, renamed consistently, and refreshed every 24 hours.

Each proxy name shows its detected country and connection type:

```text
@STenmenB 🇩🇪 VLESS/WS/TLS
@STenmenB 🇺🇸 VLESS/RAW/REALITY
```

## Which subscription should I use?

For the easiest and most reliable experience, use a **tested** subscription.
Tested proxies are checked by GitHub Actions and ordered from lowest to highest
delay.

| Client or format | Recommended tested subscription | Complete subscription |
| --- | --- | --- |
| Mihomo, Clash Meta, Clash Verge Rev | [mihomo-tested.yaml](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/mihomo-tested.yaml) | [mihomo.yaml](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/mihomo.yaml) |
| V2rayNG, Hiddify, NekoBox and Base64 clients | [tested-base64.txt](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/tested-base64.txt) | [base64.txt](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/base64.txt) |
| Plain proxy links, one per line | [tested.txt](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/tested.txt) | [all.txt](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/all.txt) |
| Mihomo proxy-provider | [proxies-tested.yaml](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/proxies-tested.yaml) | [proxies.yaml](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/proxies.yaml) |

Copy the link for your client, open its **Subscriptions** or **Profiles** page,
choose **Add from URL**, paste the link, and update the profile.

You can check the latest availability and update information for every upstream
source in [sources-status.json](https://raw.githubusercontent.com/sajjadtenmen/config/main/subscriptions/sources-status.json).

## Tested or complete?

- **Tested** files contain only proxies that worked from the GitHub runner during
  the latest update. They are already sorted by measured delay.
- **Complete** files contain every collected and supported proxy after duplicate
  removal, including entries that failed or timed out during testing.

A proxy marked as failed by GitHub may still work on your internet connection.
Routing, blocking, server load, and distance are different for every network. If
the tested list is too small or a known proxy is missing, import the complete list
and test it inside your own client.

GitHub tests each proxy with a five-second timeout. It tries Google first, then
retries failures through Cloudflare and Apple's connectivity-test page. These
results show reachability from the GitHub runner, not guaranteed speed or
availability from your location.

## Common problems

**Clash reports an error while importing YAML**

Use `mihomo-tested.yaml` or `mihomo.yaml` with a modern Mihomo/Clash Meta client.
Older Clash clients may not support newer protocols such as VLESS, REALITY, TUIC,
or Hysteria 2.

**The subscription has many proxies but few work**

Public proxies can expire quickly. Refresh the subscription, try the tested list,
and run your client's delay test. The list is rebuilt every 24 hours, but a server
can stop working at any time.

**My local test finds more working proxies than the tested list**

This is normal. Your ISP and location may reach servers that GitHub cannot. Use
the complete subscription when you want to test everything from your own network.

**Several proxies have similar names**

Names are intentionally standardized as `@STenmenB + country flag + protocol`.
YAML files add a numeric suffix when needed because Clash-compatible clients
require every proxy name to be unique.

## What the automation does

Every 24 hours the workflow:

1. Downloads all URLs listed in `sources.txt`.
2. Reads plain-text, Base64, and supported YAML subscription sources.
3. Removes duplicate configurations even when their original names differ.
4. Detects the server country and adds its flag.
5. Creates plain-text, Base64, and Mihomo/Clash subscriptions.
6. URL-tests supported proxies, sorts working entries by delay, and publishes the
   tested subscriptions.

The source-status report records when each URL was last checked and last fetched
successfully. It also includes the upstream `Last-Modified` timestamp and ETag
when the source server provides them, the number of configurations found, and the
most recent download error. A temporary failure does not erase the previous
successful timestamp.

Supported protocols include VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR,
Hysteria, Hysteria 2, and TUIC.

## Add or change sources

This section is for repository maintainers. Edit [`sources.txt`](sources.txt) and
put one subscription URL on each line. Plain proxy lists, Base64 subscriptions,
supported YAML subscriptions, and GitHub `blob` links are accepted. Empty lines
and lines beginning with `#` are ignored.

To rebuild locally:

```powershell
python -m pip install -r requirements.txt
python collector.py
```

Country detection uses `.cache/GeoLite2-Country.mmdb`. Without it, collection
still works, but unresolved servers receive the globe flag (`🌐`). The scheduled
GitHub workflow downloads the country database automatically.
