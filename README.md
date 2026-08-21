# Stratus Sift

Stratus Sift is a focused filesystem content scanner for security assessments. It scans local folders and reachable UNC/SMB paths for high-signal secrets and sensitive data without requiring the Stratus Shield platform.

## Quick start

```powershell
stratus-sift scan C:\Shares --format text
stratus-sift scan \\server\share --format snaffler --output findings.log
stratus-sift scan . --format json --output findings.json
```

Values are redacted by default. Use `--show-secrets` only when the output will be handled securely. Run `stratus-sift --help` for all options.

## Supported scope

- Windows x64 executable releases.
- Local files and folders, mapped drives, and UNC/SMB paths available to the current process.
- Text-oriented files up to 10 MiB by default.
- Human-readable, JSON, NDJSON, and Snaffler-style output.
- Bounded parallelism, inaccessible-path handling, cancellation, extension filters, and enumeration-only mode.

SharePoint, Slack, Jira, browser collection, Active Directory discovery, credential orchestration, and managed-agent functionality are not part of this release.

## Build and test

Requires the .NET 10 SDK.

```powershell
dotnet restore .\Stratus.Sift.slnx
dotnet build .\Stratus.Sift.slnx --configuration Release --no-restore
dotnet test .\Stratus.Sift.slnx --configuration Release --no-build
dotnet publish .\src\Stratus.Sift.Cli\Stratus.Sift.Cli.csproj --configuration Release --runtime win-x64 --self-contained true -p:PublishSingleFile=true
```

## Security boundary

This repository contains only scanner-owned contracts, detection logic, filesystem traversal, output formatting, tests, and release automation. It does not contain Stratus Shield source, APIs, tenant models, policies, findings, workflow, graph, evidence-management, connector-management, or remediation code.

Security reports should follow [SECURITY.md](SECURITY.md). Contributions are accepted under [CONTRIBUTING.md](CONTRIBUTING.md).
