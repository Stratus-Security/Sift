# Stratus Sift

Sift searches data you can access for secrets and sensitive information. It is built for pentesters and security teams reviewing file estates and collaboration platforms.

Choose a source, enumerate what is reachable, scan its content, then review the findings. Output can use Sift's normal console format, JSON, or Snaffler-style text.

Findings include the exact matched value and its surrounding line so a pentester can verify and document it.

## Scan sources

Sift includes commands for:

- Local files and folders.
- Mounted filesystems, mapped drives, and Windows UNC shares.
- Host and subnet-based SMB discovery, with Kerberos and NTLM support.
- Active Directory discovery in regular Windows builds.
- Microsoft 365 content in SharePoint, OneDrive and Teams channel files.
- Slack messages, attachments and official workspace exports.
- Atlassian Cloud content in Jira and Confluence.

The downloadable binaries are Native AOT builds. They include token-based Slack access, Slack export scanning, explicit SMB network targets, Microsoft 365, and Atlassian. Interactive browser automation and Active Directory auto-discovery are excluded from those binaries because their supporting libraries are not Native AOT compatible. The source tree keeps those modules for regular .NET builds.

## How Sift works

1. **Target**: the file, folder, share or connected source to inspect.
2. **Discovery**: content Sift can reach with the current account or supplied credentials. Enumeration mode lists the scope without scanning file content.
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
.\sift.exe local --path C:\Shares
.\sift.exe network --device server --snaffler --output findings.log --output-format cli
```

Linux x64:

```bash
curl -L https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-x64 -o sift
chmod +x sift
./sift local --path /srv/shared
```

macOS uses the same commands with the matching `sift-osx-*` download. Save it as `sift` and make it executable.

On Linux and macOS, mount network shares before scanning them. Windows can scan UNC paths directly.

Useful options:

```text
local --path <folder>
network --subnet <cidr>
m365 --help
slack --help
slack-export --help
atlassian --help
--enum-only
--rules <folder>
--output <path>
--output-format cli|json
--snaffler
```

Run `sift --help` to see every option.

## Output and evidence

Console output is intended for interactive triage. JSON output uses a versioned, source-neutral document that other tools can process. Snaffler-style output is available for workflows that already consume that form of finding log.

Sift records the matching rule, exact matched value and surrounding line, not a copy of the scanned file. Treat console output and saved reports as sensitive assessment material.

## Repository modules

- `Stratus.Sift.Contracts` defines versioned scan requests, targets, progress, observations and summaries.
- `Stratus.Sift.Core` contains the scanner domain, validators, content extraction, matching engine, and bundled rule catalogue.
- `Stratus.Sift.FileSystem` enumerates files, folders, access controls, and exposure.
- `Stratus.Sift.Connectors` contains the Microsoft 365, Slack, Slack export, and Atlassian Cloud source modules. The Atlassian module scans both Jira and Confluence.
- `Stratus.Sift.Cli` provides local, domain, network, Microsoft 365, Slack, Slack export, Atlassian, and saved-result analysis commands.
- `tests` covers command parsing, SMB discovery, connectors, rule matching, evidence output, and resumable output.
- `eng` contains release and public-boundary verification scripts.

Sift is licensed under [AGPL-3.0-only](LICENSE). Report security problems through [SECURITY.md](SECURITY.md) and read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.
