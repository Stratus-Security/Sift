# Stratus Sift

Sift searches files for secrets and sensitive data. It runs on its own and does not need Stratus Shield.

Matched values are hidden by default. Use `--show-secrets` only when you can protect the output.

## Download

Download the archive for your system from the [latest release](https://github.com/Stratus-Security/Sift/releases/latest).

| System | x64 | Arm64 |
| --- | --- | --- |
| Windows | [ZIP](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-win-x64.zip) | [ZIP](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-win-arm64.zip) |
| Linux | [tar.gz](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-linux-x64.tar.gz) | [tar.gz](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-linux-arm64.tar.gz) |
| macOS | [tar.gz](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-osx-x64.tar.gz) | [tar.gz](https://github.com/Stratus-Security/Sift/releases/latest/download/stratus-sift-osx-arm64.tar.gz) |

You can check a download against [SHA256SUMS.txt](https://github.com/Stratus-Security/Sift/releases/latest/download/SHA256SUMS.txt). Release binaries are not code-signed yet.

## Use Sift

Windows:

```powershell
.\stratus-sift-win-x64.exe scan C:\Shares
.\stratus-sift-win-x64.exe scan \\server\share --format snaffler --output findings.log
```

Linux or macOS:

```bash
tar -xzf stratus-sift-linux-x64.tar.gz
./stratus-sift-linux-x64 scan /srv/shared
```

On Linux and macOS, mount network shares before scanning them. Sift can scan Windows UNC paths directly when it runs on Windows.

Useful options:

```text
--format text|json|ndjson|snaffler
--output <path>
--enumerate-only
--extensions .txt,.json,.env
--exclude-dirs cache,temp
--show-secrets
```

Run `stratus-sift --help` to see every option.

## What it scans

Sift scans local files, folders, mounted shares and Windows UNC paths that your account can already access. It reads text-oriented files up to 10 MiB by default and skips common build and source-control folders.

It does not include SharePoint, Slack, Jira, browser collection, Active Directory discovery, credential management or Stratus Shield agent features.

## Build from source

Install the .NET 10 SDK, PowerShell 7.2 and the Native AOT tools for your system. AOT builds must run on the target operating system.

```powershell
dotnet restore .\Stratus.Sift.slnx --locked-mode
dotnet build .\Stratus.Sift.slnx --configuration Release --no-restore
dotnet test .\Stratus.Sift.slnx --configuration Release --no-build
.\eng\Build-Release.ps1 -Version 0.1.0 -RuntimeIdentifier win-x64
```

Use `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`, `win-x64` or `win-arm64` for `RuntimeIdentifier`. The build script only accepts the runtime that matches the current machine.

Sift is licensed under [AGPL-3.0-only](LICENSE). Security reports belong in [SECURITY.md](SECURITY.md). See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.
