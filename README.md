# Config subscription collector

This repository combines proxy configurations from multiple public text files or
subscription URLs. It removes duplicates, detects the server country, and renames
every entry in this format:

```text
@STenmenB 🇩🇪 VLESS/WS/TLS
@STenmenB 🇺🇸 VLESS/RAW/REALITY
```

## Add sources

Edit [`sources.txt`](sources.txt) and put one URL on each line. The URL may return
plain proxy links or a Base64-encoded subscription. GitHub `blob` links are
accepted and converted to raw links automatically. Lines beginning with `#` are
ignored.

Supported schemes are VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR, Hysteria,
Hysteria 2, and TUIC.

## Outputs

The automation creates:

- `subscriptions/all.txt`: one renamed proxy link per line.
- `subscriptions/base64.txt`: the same complete list encoded as a standard Base64
  subscription.

Duplicate detection ignores the old display name. For VMess, it ignores `ps`; for
URI-based protocols, it ignores the `#fragment`. Therefore, the same server config
with different names is only included once.

## Automation

The GitHub Actions workflow runs once every 24 hours and can also be started from
the **Actions** tab with **Run workflow**. It downloads a current GeoLite country
database, rebuilds both output files, and commits them only when they change.

If the default branch is protected against direct pushes, allow GitHub Actions to
push or adapt the final workflow step to open a pull request.

## Run locally

```powershell
python -m pip install -r requirements.txt
python collector.py
```

Without `.cache/GeoLite2-Country.mmdb`, collection still works but unresolved
countries use the globe flag (`🌐`). The scheduled workflow downloads the database
automatically.
