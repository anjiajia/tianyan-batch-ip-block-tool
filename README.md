# SOC Batch IP Block Tool

Local GUI tool for importing SOC alert exports, extracting IPs, filtering whitelist/duplicates, and batch blocking them on firewall devices.

## Start

```powershell
node src/server.js
```

Open:

```text
http://127.0.0.1:8787
```

If the port is occupied:

```powershell
$env:PORT=8790; node src/server.js
```

## Supported input

- CSV
- TXT
- XLSX
- Manual pasted IP text

## Current block adapters

The device adapters were adjusted after checking `SecAegis/SecAutoBan` under `device/block`.

Implemented in this GUI:

- Qianxin Firewall, SecAutoBan style: login `/v1.0/login/`, cookie token, `/v1.0/rest/`, `addr_blacklist.add_batch_blacklist`
- TopSec Firewall, SecAutoBan style: login `/home/login/`, parse token envelope, `blackListSpread/add`
- Sangfor Firewall, SecAutoBan style: login `/api/v1/namespaces/@namespace/login`, token cookie, `whiteblacklist` BLACK entry
- OPNsense: alias util API with API key/secret basic auth
- Check Point Management API: login sid, add/find host, add to group, publish, logout
- Generic REST JSON fallback
- Palo Alto PAN-OS XML API as a generic URL template

Not executed directly yet:

- RouterOS API: SecAutoBan uses the RouterOS binary API library, so this needs a sidecar/helper.
- BGP/GoBGP: SecAutoBan runs local `gobgp` commands; this GUI does not run route-changing commands yet.
- TCP reset: requires packet capture/injection permissions and is outside this GUI scope.

## Safety

Dry-run is enabled by default. Keep it enabled until the parsed IP list and adapter configuration are confirmed.

Runtime audit logs are written to `data/audit-log.jsonl` and ignored by git.

## Release, signing, and auto update

Tagged versions such as `v0.1.9` are built by GitHub Actions and uploaded to GitHub Releases. The desktop app uses GitHub Releases as the update source through `electron-updater`; packaged apps check for updates after startup.

Code signing is optional until certificates are available:

- Windows signing: add `WIN_CSC_LINK` and `WIN_CSC_KEY_PASSWORD` GitHub Secrets, or use `CSC_LINK` and `CSC_KEY_PASSWORD`.
- macOS signing/notarization: add `CSC_LINK`, `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, and `APPLE_TEAM_ID`.
- If these secrets are absent, CI still builds unsigned packages.
