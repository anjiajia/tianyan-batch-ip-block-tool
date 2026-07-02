# SignPath Foundation Windows Signing Application

This project is being prepared for free Windows code signing through SignPath Foundation.

## Preferred Provider

SignPath Foundation

- Website: https://signpath.org/
- Apply: https://signpath.org/
- Purpose: free Windows Authenticode signing for qualifying open source projects

## Project Details

- Project name: SOC Batch IP Block Tool
- Repository: https://github.com/anjiajia/tianyan-batch-ip-block-tool
- Release page: https://github.com/anjiajia/tianyan-batch-ip-block-tool/releases
- Application type: Electron desktop application
- Primary platform needing signing: Windows
- Windows artifacts:
  - NSIS installer
  - Portable executable
- Build command: `npm run dist:win`
- CI workflow: `.github/workflows/windows-release.yml`

## Short Description For Application Form

SOC Batch IP Block Tool is a local desktop utility for SOC teams. It imports alert exports, extracts IP addresses, filters duplicates and whitelisted ranges, and performs dry-run or controlled batch block/unblock operations against firewall APIs. It is designed for cautious security operations with dry-run enabled by default, local configuration, and audit logs.

## Why Signing Is Needed

Windows users currently receive warnings when running unsigned Electron packages. Code signing is needed so users can verify that the downloaded installer or portable executable was produced from the public source repository and was not modified after release.

## Open Source Readiness Checklist

- [ ] Repository is public.
- [ ] An OSI-approved open source license is added, such as MIT, Apache-2.0, or GPL-3.0.
- [ ] Release downloads are free.
- [ ] Windows builds are produced by GitHub Actions.
- [ ] `package-lock.json` is committed for reproducible dependency installation.
- [ ] A tagged release build, such as `v0.1.11`, is available for SignPath review.
- [ ] No secrets, real firewall addresses, credentials, or customer data are committed.

## Suggested SignPath Project Settings After Approval

- Project slug: `tianyan-batch-ip-block-tool`
- Repository URL: `https://github.com/anjiajia/tianyan-batch-ip-block-tool`
- Trusted build system: GitHub Actions
- Release signing branch/tag rule: `v*` tags
- Artifact configuration:
  - Sign NSIS installer with Authenticode.
  - Sign portable executable with Authenticode.
  - If SignPath recommends deep signing, sign embedded `.exe` and `.dll` files before re-packaging.

## Information The Maintainer Must Provide

- Maintainer name and contact email.
- Confirmation that the repository is intentionally open source.
- Chosen license.
- Confirmation that downloads are free.
- Confirmation that the software does not contain malware, licensing circumvention, or credential harvesting behavior.

## After SignPath Approval

SignPath will provide project-specific integration details. Add their required GitHub Action or API submission step after the unsigned Windows build step, then download/upload the signed artifacts as release assets.
