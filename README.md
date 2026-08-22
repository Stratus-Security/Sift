# Stratus Sift

Sift searches accessible data for secrets and sensitive information. It is intended for operator-led security assessments across file estates and collaboration platforms.

The workflow is simple: choose a source, enumerate what is reachable, scan its content, then review a small set of useful observations. Output can be written in human-readable, JSON, NDJSON or Snaffler-compatible form.

Findings include the exact matched value and its surrounding line so a pentester can verify and document it.

## Scan sources

The current public release scans:

- Local files and folders.
- Mounted file systems and mapped drives.
- Windows UNC shares that the current account can access.

The wider Sift CLI also has source modules for:

- Active Directory and subnet-based SMB discovery, with Kerberos and NTLM support.
- Microsoft 365 content in SharePoint, OneDrive and Teams channel files.
- Slack messages, attachments and official workspace exports.
- Atlassian Cloud content in Jira and Confluence.

These source modules are being moved into the public package in stages. The downloadable binary currently contains the file-system scanner only, so it does not yet expose the `domain`, `network`, `sharepoint`, `slack`, `slack-export` or `atlassian` commands.

## How Sift works

1. **Target**: the file, folder, share or connected source to inspect.
2. **Discovery**: the content Sift can reach with the supplied account or token. Enumeration mode lists the scope without reading file content.
3. **Rules**: focused detectors for credentials, private keys, tokens, payment data and other sensitive values.
4. **Observation**: a rule match with its location, severity, confidence, exact value and surrounding context.

Sift does not create access that you do not already have. Inaccessible paths are reported and skipped. Reparse points are not followed during recursive file-system scans.

## Download

Download the binary for your system from the [latest release](https://github.com/Stratus-Security/Sift/releases/latest).

| System | x64 | Arm64 |
| --- | --- | --- |
| Windows | [EXE](https://github.com/Stratus-Security/Sift/releases/latest/download/sift.exe) | [EXE](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-win-arm64.exe) |
| Linux | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-x64) | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-arm64) |
| macOS | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-osx-x64) | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-osx-arm64) |

Check downloaded files against [SHA256SUMS.txt](https://github.com/Stratus-Security/Sift/releases/latest/download/SHA256SUMS.txt). Release binaries are not code-signed yet.

## Quick start

Windows x64:

```powershell
Invoke-WebRequest https://github.com/Stratus-Security/Sift/releases/latest/download/sift.exe -OutFile sift.exe
.\sift.exe scan C:\Shares
.\sift.exe scan \\server\share --format snaffler --output findings.log
```

Linux x64:

```bash
curl -L https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-x64 -o sift
chmod +x sift
./sift scan /srv/shared
```

macOS uses the same commands with the matching `sift-osx-*` download. Save it as `sift` and make it executable.

On Linux and macOS, mount network shares before scanning them. Windows can scan UNC paths directly.

Useful options:

```text
--format text|json|ndjson|snaffler
--output <path>
--enumerate-only
--extensions .txt,.json,.env
--exclude-dirs cache,temp
```

Run `sift --help` to see every option.

## Output and evidence

Text output is intended for interactive triage. JSON and NDJSON use versioned, source-neutral contracts so results can be processed by other tools. Snaffler output is provided for workflows that already consume that style of finding log.

Sift records the matching rule, exact matched value and surrounding line, not a copy of the scanned file. Treat console output and saved reports as sensitive assessment material.

## Repository modules

- `Stratus.Sift.Contracts` defines versioned scan requests, targets, progress, observations and summaries.
- `Stratus.Sift.Core` is the canonical tenant-neutral matching and filesystem scanning engine. Other applications consume packages built from this source instead of keeping their own scanner copy.
- `Stratus.Sift.Cli` contains argument handling, output formatting and platform checks.
- `tests` covers argument handling, detection, evidence output, output contracts and supported platforms.
- `eng` contains release and public-boundary verification scripts.

Sift is licensed under [AGPL-3.0-only](LICENSE). Report security problems through [SECURITY.md](SECURITY.md) and read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.
