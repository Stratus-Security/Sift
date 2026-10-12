# Changelog

## Unreleased

### Microsoft 365 coverage

- Scan storage and all nine implemented service adapters by default using existing access: Teams, Planner, To Do, OneNote, shared mail, SharePoint Embedded, Viva Engage, Power BI and Power Platform. Only additional permission consent requires `--request-additional-permissions`; Global Administrator is not required for content already accessible through a suitably consented application.
- Include hidden, specialized and custom file libraries, Site Assets, page libraries, galleries and accessible preservation libraries. Exclude only each library's system `Forms` directory, while including ordinary and nested folders with similar names.
- Inspect subsites, generic-list fields and attachments, custom library columns, modern page canvas text, historical files and recycle-bin metadata. Reconcile OneDrive discovery and supplement accessible/shared files through supported search APIs.
- Follow accessible OneDrive/SharePoint shortcuts with target-identity deduplication, cycle detection, bounded depth and continuation limits. Target changes remain discoverable on resume without relying on the source shortcut's delta state.
- Inspect sharing identities, roles, inheritance and guest membership. Reconcile delegated Graph permissions against native SharePoint permissions; preserve unknown/incomplete exposure when access cannot establish a complete assessment.
- Convert `.loop`, `.fluid`, `.whiteboard` and `.wbtx` files to bounded searchable text through Graph HTML conversion. Retain original file identity and metadata, and leave unsupported historical conversions incomplete. Converted HTML does not trigger link crawling.
- Support explicit shared-mailbox targets, including directory SMTP aliases, nested/hidden folders, message bodies and supported attachments. Exclude the signed-in user's own mailbox. Embedded containers require explicit container/type targets and associated grants.

### Document and archive inspection

- Add PowerPoint and OneNote binary extraction alongside Word, Excel and PDF, including supported Office 97–2003 formats and Excel `.xlsb`. Include hidden worksheets/slides, notes, comments, stored formulas, related text parts and supported embedded documents.
- Extend OneNote extraction to notebook packages, supported attachments and stored recognition text. Bound document history, nested documents, expanded bytes and extraction output; retain available findings when extraction is incomplete.
- Inspect supported archive entries even when no rule matches the outer archive filename. Include ZIP, 7z, RAR, TAR and common compressed TAR wrappers, with shared entry, nesting, buffering and expansion limits.
- Recognize valid empty TAR archives and report zero-byte, unrecognizable or malformed payloads as incomplete with concise diagnostics. Preserve archive entry paths and partial findings; unavailable content remains pending.
- Enable bounded image/PDF OCR for binary CLI scans when Tesseract is installed. Report unavailable OCR as incomplete when required to inspect content. Office installation, macro execution and external-document link traversal are not required.
- Extend bundled document rule profiles and identity/financial rules to the supported formats. Custom rule extension lists remain authoritative.

### Network scans and resume

- Add `network --targets-file` (`--target-file`, `-t`) for mixed IPv4/IPv6 addresses, hostnames and CIDRs, one per line. Accept comments, whitespace, optional quotes, UTF-8 and BOM-marked UTF-16; validate entries before discovery and deduplicate repeated hosts/ranges within bounded expansion limits.
- Keep interrupted or failed files/subtrees pending, and advance checkpoints only after processing and journal updates succeed. Detect same-size remote edits using server versions/timestamps; refresh metadata and skip unchanged content downloads on resume.
- Harden resume-journal recovery, cleanup and synchronization with `System.Threading.Lock` for synchronous state and an asynchronous gate for durable writes. Keep partial progress usable without treating omitted content as complete.
- Honor server throttling across workers and enforce configured head-sampling limits even when a server ignores byte ranges. Large ordinary text files continue to use deliberate sampling for efficiency.
- Group expected access, missing-file, lock and unavailable-source diagnostics. Keep genuine failures visible through bounded warning samples and summaries, with exit code `3` for incomplete scans.
- Refresh locked dependencies, licensed interoperability fixtures and cross-platform Native AOT build inputs.

### API correctness fixes

- Correct SharePoint accessible-file search sorting to `docid:ascending`, eliminating the misleading search-syntax HTTP 400.
- Continue native sharing reconciliation when delegated Graph directory lookups encounter unavailable principals; retain incomplete results when reconciliation also fails.
- Exclude Graph's current version from historical downloads and count only earlier versions against the history limit.
- Normalize CAML `FileRef` paths that omit the leading slash, reject sibling-library paths, and consume rowset pagination independently of change-token pagination. Repeated continuations stop without premature checkpoints.
- Classify wrapped Graph library-field 403/404 failures as expected while retaining content findings and incomplete state. Genuine request errors remain visible.

### Validation and limits

- 1,102 regression tests passed. Windows x64 Native AOT publication, executable smoke checks and public-boundary verification passed.
- Bounded read-only tenant checks returned 60 successful baseline API responses and 21 successful production-reader rechecks. Sampled storage, Teams, OneNote, Planner, To Do list and shared-mail content requests succeeded. Current Loop/Whiteboard conversion and Loop history also passed with existing delegated access.
- Live checks do not establish an entire tenant inventory or equivalent permissions for every app registration. Empty collections verify request acceptance only. Power BI, Viva Engage, Power Apps/Dataverse and Embedded APIs remain unverified live where grants or targets were unavailable; app-only and sovereign-cloud modes were not exercised live.
- An older sampled Whiteboard version remained unreadable as converted text, and an unresolved directory sharing group remained unknown/incomplete. These conditions preserve other findings and prevent false completion.
- Forms questions/responses, Planner Premium/Project completeness, Power Platform content outside Dataverse, semantic-model row queries and original recycle-bin payload downloads remain outside the implemented coverage. Supported storage exports can still be scanned.
- Ollama is optional and is called only when local LLM validation is explicitly enabled. Normal scans and the tenant validation above require no LLM.
