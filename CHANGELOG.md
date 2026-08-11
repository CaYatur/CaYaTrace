# Changelog

All notable changes to CaYaTrace are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-11

First public preview. The engine and remediation path are real; the workbench UI and the
network layer are not yet built. See [ROADMAP.md](docs/ROADMAP.md).

### Added

**Correlation**
- Process identity keyed on the kernel process start key, with `(PID, creation time)` as a
  fallback, so PID reuse cannot merge unrelated subtrees
- Per-PID generation tracking: an event resolves to the process alive at its timestamp
- Scope adoption for processes the parent chain misses — SCM service starts, COM activations,
  scheduled tasks
- FileObject and FileKey name resolution, bounded with counted LRU eviction
- Registry key-control-block resolution, including rundown seeding
- 5-tuple flow attribution preserving how the join was made
- Path and registry canonicalization with portable tokenization

**Collection**
- Real-time kernel ETW: process, thread, image, file, registry, TCP/UDP
- Registry value recovery with baseline seeding, so writes read as `before → after`
- Remote-thread creation detected as a distinct signal
- Background image hashing, Authenticode verification, and token integrity level
- Before/after inventories: services, scheduled tasks, autoruns, persistence surfaces,
  installed programs, drivers, certificate stores, hosts file
- Snapshot diff attributed to a process only when a live event corroborates it
- Subject launched suspended so no early activity is missed

**Storage**
- Per-session SQLite in WAL mode, one self-contained file
- Append-only JSONL journal so a hard kill still leaves evidence
- Bounded ring buffer that drops and counts rather than stalling a callback thread
- Data-quality accounting surfaced in the session header and every export

**Remediation**
- Non-overridable deny list: Windows-owned paths, boot-critical registry subtrees, core
  services, shared containers
- Planner proposing only artifacts the subject created, cancelling ones it later removed
- Fingerprint re-verification on the target machine before any action
- Quarantine instead of deletion; `.reg` export before registry changes
- Rollback journal written as the run proceeds
- Dry run by default
- `.ctpkg` portable removal packages with plan integrity hashing

**Application**
- One executable routing to workbench, `trace`, `report`, `remediate`, and `agent` modes
- Text causal-tree renderer

### Known limitations

- Kernel tracing requires an elevated process
- Network evidence is limited to kernel flow events; DNS, TLS metadata, and HTTP(S) URL
  capture are designed but not implemented
- Workbench UI, multi-VM comparison, VirusTotal, Ollama, and HTML export are not implemented
- Packages are not signed; the plan hash detects damage, not forgery

### Notes

Embedding removal payloads into the executable was tested and rejected: patching PE resources
into a .NET single-file bundle truncated a 67 MB host to 9.6 MB and corrupted it. Packages
ship as `.ctpkg` sidecars. See [PACKAGE-FORMAT.md](docs/PACKAGE-FORMAT.md).

[0.1.0]: https://github.com/CaYatur/CaYaTrace/releases/tag/v0.1.0
