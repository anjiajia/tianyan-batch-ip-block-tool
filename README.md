# SOC Batch IP Block Tool

A local desktop tool for SOC teams to import alert exports, extract IP addresses, filter whitelist/duplicates, and batch block or unblock IPs on firewall devices.

The project is designed for cautious security operations: dry-run is enabled by default, every run is written to an audit log, and firewall credentials can be kept local.

## Features

- Import SOC alert files in CSV, TXT, and XLSX formats.
- Paste IP addresses manually when no export file is available.
- Filter duplicate IPs, private/reserved IPs, and custom whitelist ranges.
- Batch block selected IPs through firewall adapters.
- Batch unblock selected IPs through the same firewall configuration.
- Dry-run mode shows the exact operation result without calling firewall APIs.
- Save/load local firewall configuration, with password/token storage disabled by default.
- View audit records for block, unblock, and dry-run operations.
- Export execution results as CSV.
- Desktop builds for Windows, macOS, and Linux through GitHub Releases.
- Packaged desktop app checks GitHub Releases for updates after startup.

## Download

Go to the project Releases page and download the package for your system:

https://github.com/anjiajia/tianyan-batch-ip-block-tool/releases

- Windows: `windows-x64-setup.exe` or `windows-x64-portable.exe`
- macOS: `mac-arm64.zip`
- Linux: `linux-x86_64.AppImage` or `linux-x64.tar.gz`

For Windows testing, the portable package is the fastest path because it does not require installation.

## Quick Start

1. Open the desktop app.
2. Import a SOC alert export file, or paste IPs into the manual input box.
3. Confirm the parsed IP list and whitelist filtering result.
4. Select the firewall type and fill in the firewall connection settings.
5. Keep dry-run enabled and click batch block or batch unblock.
6. Check the result output and audit record.
7. Disable dry-run only after the configuration has been verified against the real firewall.

## Supported Input

- CSV
- TXT
- XLSX
- Manual pasted IP text

## Firewall Adapters

Implemented adapters:

- Qianxin Firewall, SecAutoBan style: login `/v1.0/login/`, cookie token, `/v1.0/rest/`, `addr_blacklist.add_batch_blacklist`.
- TopSec Firewall, SecAutoBan style: login `/home/login/`, parse token envelope, `blackListSpread/add`.
- Sangfor Firewall, SecAutoBan style: login `/api/v1/namespaces/@namespace/login`, token cookie, `whiteblacklist` BLACK entry.
- OPNsense: alias util API with API key/secret basic auth.
- Check Point Management API: login sid, add/find host, add to group, publish, logout.
- Generic REST JSON fallback.
- Palo Alto PAN-OS XML API as a generic URL template.

Known items not executed directly in the GUI:

- RouterOS API: SecAutoBan uses the RouterOS binary API library, so this needs a sidecar/helper.
- BGP/GoBGP: SecAutoBan runs local `gobgp` commands; this GUI does not run route-changing commands.
- TCP reset: requires packet capture/injection permissions and is outside this GUI scope.

## Configuration Notes

The firewall configuration panel supports:

- Base URL
- Username / API key
- Password / API secret
- Object name, such as alias/group/list name
- Generic HTTP endpoint, method, success status codes, token header, and payload template
- TTL, reason, concurrency, dry-run, and TLS verification options

Local configuration can be saved from the UI. Passwords and tokens are not saved unless the `Save password / Token` option is explicitly checked.

## Dry-run Behavior

Dry-run does not call the firewall API. It only simulates the selected action and writes a result such as `DRY_RUN` to the output and audit log.

Use dry-run before every new firewall integration or configuration change.

## Audit Logs

Runtime audit logs are written locally:

```text
data/audit-log.jsonl
```

In the packaged desktop app, the audit log is stored under the app user-data directory. Audit records include action type, adapter, dry-run flag, total count, success/failure count, reason, and per-IP results.

## Development

Install dependencies:

```powershell
npm install
```

Start the local web app:

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

Run the Electron shell:

```powershell
npm run electron
```

Build Windows packages locally:

```powershell
npm run dist:win
```

## Release and Auto Update

Tagged versions such as `v0.1.10` are built by GitHub Actions and uploaded to GitHub Releases.

The desktop app uses GitHub Releases as the update source through `electron-updater`. Packaged apps check for updates after startup. Update metadata files such as `latest.yml`, `latest-mac.yml`, `latest-linux.yml`, and `.blockmap` files are uploaded with release assets.

## Code Signing

Code signing is optional until certificates are available.

Windows signing:

- This repository is prepared for free open-source Windows signing through SignPath Foundation.
- Apply at https://signpath.org/apply with the repository URL and the details in `docs/signpath-windows-application.md`.
- The Windows CI build is defined in `.github/workflows/windows-release.yml` and produces unsigned NSIS and portable artifacts for SignPath review.
- After SignPath approves the project, add their project-specific signing step to the workflow and publish the signed artifacts.
- If using a traditional code signing certificate instead, add `WIN_CSC_LINK` and `WIN_CSC_KEY_PASSWORD` GitHub Secrets, or use `CSC_LINK` and `CSC_KEY_PASSWORD`, then run `npm run dist:win:signed`.

macOS signing/notarization:

- Add `CSC_LINK`, `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, and `APPLE_TEAM_ID`.
- Current CI builds unsigned macOS packages until these secrets are configured.

If signing secrets are absent, CI still builds unsigned packages.

## Safety

- Keep dry-run enabled until real firewall behavior is confirmed.
- Review the parsed IP list before running any real block or unblock action.
- Keep whitelist ranges up to date.
- Store passwords/tokens only on trusted workstations.
- Validate vendor-specific unblock behavior during real device integration.
