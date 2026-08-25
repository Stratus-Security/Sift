# Stratus Sift

## What's this?
Sift is a tool developed by Stratus Security to improve our penetration testing, open-sourced to help improve data security for pentesters and security teams.
It searches data you can access for secrets and sensitive information across a number of platforms and it's *very* effective.

## TL;DR; How do i run this?
The quickest way if you're familiar with snaffler:
```
.\sift.exe local --path C:\
```

For more advanced commands, check out the [how to](#how-do) section below. Very recommended.

## Why make this? Is this Snaffler?
Like most things we make, Sift is a tool developed out of frustration. For a while we used a custom fork of Snaffler like many in the industry, but ultimately it became harder to continue maintaining the fork than it was to just make it from scratch.

Sift was made with performance and extensibility in mind, to name a few great improvements over existing solutions:
- No framework dependancies + compiled executables (thanks NativeAoT!)
- Connector flexibility: It's modular to allow scanning anything with a small adapter (Currently supports local drives, local network/subetnets, AD, SharePoint, Slack and Atlassian (Jira+Confluence)). Suggestions for more are welcome!
- Resumability: Every scan command can continue from durable checkpoints, so an interrupted scan only repeats a small amount of work.
- Performance: Local and SMB scans use a bounded high-throughput pipeline with compiled rules and reusable scan state. See [Benchmarks](#benchmarks) for the test method and measured results.
- Explicit authentication: No more runas! Kerberos! Pass the hash! ???! Profit!
- Safety features: e.g. Dodges unsynced OneDrive files instead of filling up a servers drives by accessing it all... hypothetically.
    - If you're worried about coverage, OneDrive backs onto SharePoint so it will be better if you scan SharePoint than local drives :D
- File support: You can (optionally) include binary files like word docs, etc. Support isn't perfect yet but you can't have everything!
- AI: We love some AI, but we also love privacy. and cake. The data gathered by Sift is extremely sensitive, so we support AI filtering to remove false positives but only using local LLMs.
- Cross-Platform: The tool works on Macs, Windows and Linux (with varying feature support, of course!)
- Throttling: The pentesting CLI uses the available machine by default. Use `--threads` and `--max-read-mib-per-second` when scanning a sensitive production target.
- Fingerprints: Full coverage validated against the Snaffler rules library with much more and some refined. Code-defined validators are also supported to do more advanced checks and reduce false positives 📔
- DNS: Custom DNS servers for those times when you want to use computer names from a non-corp, wowee!

## This is confusing, how do I just find the features I want?
The good ol' help flag will show the available commands:

```
> .\sift.exe --help

Usage:
  sift [command] [options]

Commands:
  local      Scan a local folder
  domain     Crawl the current Active Directory domain by auto-discovering accessible SMB shares. Kerberos is preferred, with per-host NTLM fallback
  network    Crawl SMB targets on a subnet or a single device. Kerberos is preferred, with per-host NTLM fallback
  m365       Scan Microsoft 365 content, including SharePoint, OneDrive, and Teams channel files
  slack      Scan accessible Slack channel messages and attachments
  atlassian  Scan accessible Jira projects and Confluence pages, blog posts, comments, and attachments
  analyze    Replay saved JSON findings and optionally re-run LLM validation offline
```

and slap a command on to get help for that specific one:
```
> .\sift.exe domain --help

Usage:
  sift domain [options]

Options:
  -b, --binary                                  Include binary files in scan.
  -e, --enum-only                               Enumerate discovered drives, shares, or roots and exit without scanning file content.
  --llm-validate                                Validate classifier matches with a local Ollama model before reporting findings.
  --llm-sensitive-only                          Only keep findings that the LLM classifies as sensitive. Requires --llm-validate.
  --ollama-url <ollama-url>                     Base URL for the Ollama server. [default: http://localhost:11434]
  --ollama-model <ollama-model>                 Ollama model to use for classifier validation. If omitted with --llm-validate, an interactive prompt is used when possible.
  --llm-timeout-seconds <llm-timeout-seconds>   Timeout for each Ollama validation request in seconds. [default: 20]
  --snaffler, --snaffler-mode                   Render console and CLI text output in Snaffler's logging style.
  -r, --rules <rules>                           Path to a folder containing classifier/policy files (JSON). If not provided, bundled defaults are used.
  -o, --output <output>                         Write scan output to a file. Resumed scans append; new scans replace it.
  -f, --output-format <output-format>           Output file format. Supported values: cli, json.
  --resume                                      Continue from durable checkpoints saved by an earlier scan with the same target, credentials, rules, and scan settings.
  -u, --username <username>                     Windows username for SMB/LDAP impersonation. Accepts user, domain\user, or user@domain.
  -p, --password <password>                     Windows password for SMB/LDAP impersonation.
  -d, --domain <domain>                         Windows/AD domain for impersonation when --username is not already qualified.
  -l, --local                                   Use the local machine account namespace instead of a domain account.
  -k, --kerberos                                Require Kerberos for LDAP and SMB authentication and reject the default per-host NTLM fallback. Use DNS hostnames for service principals.
  --dns-server <dns-server>                     Send A, AAAA, and PTR queries directly to this DNS server IP address.
  -dc, --domain-controller <domain-controller>  Domain controller hostname or IP address to use for LDAP discovery if auto-discovery fails.
  -?, -h, --help                                Show help and usage information
```

## Benchmarks

To quantify the speed, we ran benchmarks with synthetic repos of files to compare performance. Note that a small patch was made to snaffler to allow it to finish without waiting for it's minutely check-in to keep results fair.

Here is the 3 benchmarks done with the current Sift and Snaffler builds (24th August 2026).
| Scenario | Sift | Snaffler |
| --- | ---: | ---: |
| 250,000 small files | 10.61 s | 25.48 s |
| 5.5 GiB content throughput | 0.69 s | 6.32 s |
| Deep and wide tree | 1.12 s | 2.37 s |

All tests were run 3 times and the average results are aggregated in the table below:
| Metric | Snaffler 1.0.244 | Sift | Improvement |
| --- | ---: | ---: | ---: |
| Duration | 34.18 s | 12.42 s | 2.75x faster |
| Total CPU time | 276.56 s | 62.11 s | 4.45x less CPU time |
| Average CPU load | 25.3% | 15.6% | 1.62x lower load |
| Average memory | 337 MiB | 92 MiB | 3.68x lower memory |
| Memory-time | 11.24 GiB·s | 1.11 GiB·s | 10.1x less RAM-time |
| Peak memory | 429.5 MiB | 102.2 MiB | 4.20x lower peak |

Note that default is unlimited (as used above) but resource limits can be set explicitly when you need to reduce impact:

```powershell
.\sift.exe local --path C:\Shares --threads 8 --max-read-mib-per-second 32
```

## How Do?
In case you're wondering how to do the things, here are a few examples to get your started.

Scan a specific computer:
```powershell
.\sift.exe network --device SRV01 --output srv01-findings.log
```

Scan all shares in a domain from an unmanaged device:
```powershell
.\sift.exe domain --username pentester --password '<password>' --domain CONTOSO --domain-controller 10.0.0.10
```

Scan a subnet with a local admin:
```powershell
.\sift.exe network --subnet 10.0.0.0/24 --username Administrator --password '<password>' --local --output findings.log
```

Scan a local disk and then refine the results on another machine with a local LLM:
```powershell
.\sift.exe local --path C:\ --output findings.json --output-format json
.\sift.exe analyze --input findings.json --llm-validate --ollama-model gemma4:31b --sensitive-only --output findings.log
```

Analyze results in a terminal without rescanning:
```powershell
.\sift.exe analyze --input findings.json --snaffler
```

Continue a previous or incomplete scan:
```powershell
.\sift.exe local --path C:\ --resume --output findings.json --output-format json
.\sift.exe domain --resume
.\sift.exe network --subnet 10.0.0.0/24 --resume
.\sift.exe m365 --resume --output m365-findings.json --output-format json
```

`--resume` works with local, domain, network, Microsoft 365, Slack, and Atlassian scans. During active processing, Sift stages compact fingerprints in buffered sequential writes and makes them durable about every 30 seconds. It also stores source paging cursors where the provider supports them. The output file is flushed before a checkpoint advances. Use the same command and output path to continue one report; output is optional if you only need results in the terminal.

Checkpoints are selected automatically from the target, account or credentials, rules, and relevant scan settings. They contain opaque fingerprints and continuation state, not findings or credentials. Changed files are scanned again. Journals are capped at 128 MiB each, old journals expire after 30 days, and the checkpoint directory is kept within 512 MiB by default. A normal run starts over and replaces its output; a resumed run skips completed unchanged content and appends to its output. `--resume` cannot be combined with `--enum-only`.

## Scan sources

Sift includes commands for:

- Local files and folders.
- Mounted filesystems, mapped drives, and Windows UNC shares.
- Host and subnet-based SMB discovery, with Kerberos and NTLM support.
- Active Directory discovery in regular and Native AOT Windows builds, with paged LDAP queries and signed, sealed authentication.
- Microsoft 365 content in SharePoint, OneDrive and Teams channel files.
- Slack messages and attachments.
- Atlassian Cloud content in Jira and Confluence.

## Download

Download the binary for your system from the [latest release](https://github.com/Stratus-Security/Sift/releases/latest).

| System | x64 | Arm64 |
| --- | --- | --- |
| Windows | [EXE](https://github.com/Stratus-Security/Sift/releases/latest/download/sift.exe) | [EXE](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-win-arm64.exe) |
| Linux | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-x64) | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-linux-arm64) |
| macOS | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-osx-x64) | [Binary](https://github.com/Stratus-Security/Sift/releases/latest/download/sift-osx-arm64) |

Check downloaded files against [SHA256SUMS.txt](https://github.com/Stratus-Security/Sift/releases/latest/download/SHA256SUMS.txt). Release binaries are not code-signed yet.

Sift is licensed under [AGPL-3.0-only](LICENSE). Report security problems through [SECURITY.md](SECURITY.md) and read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.

🪲 If there's any problems, please feel free to open an issue (or PR!) 🪲
