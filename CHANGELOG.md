# Changelog

All notable changes to CaYaTrace are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-12

First public release. One portable executable: a workbench window for the whole workflow, and
the same capabilities as command-line verbs for scripted and sandbox use.

### Added

**The workbench**
- Record a session from the window — launch a program, attach to a running one, or watch the
  whole machine — with live event counters and automatic loading when it stops
- Findings, causal tree, and a network view showing which process asked for which URL
- Session browser, export dialog, removal-plan review, local-model assistant, fleet host
- Turkish and English throughout, following the Windows display language, switchable in place
- `--view` opens a section directly; `--screenshot` renders one to a PNG

**Network**
- DNS queries and answers attributed to the requesting process
- TLS handshake metadata, and full URLs from the Windows HTTP stacks
- Packet capture through the Windows packet monitor, correlated back to processes by 5-tuple
- Opt-in intercepting proxy with a per-session certificate authority, verified removal, and a
  consent step that requires typing a word

**Analysis**
- Path templating and multi-machine comparison, turning guessed path patterns into measured
  ones
- Risk scoring with visible reasons, never an opaque number
- Local model support with capability probing, so a model is measured against known answers
  before any of its output is shown
- VirusTotal reputation by hash; the client cannot upload a file by construction

**Export**
- HTML, JSON, CSV, and text, with per-category selection and minimal / standard / full depth
- The HTML report is the workbench markup with the session inlined, carrying both languages
  and its own switch

**Fleet**
- Paired, encrypted host-to-agent channel over ephemeral ECDH P-256 and ChaCha20-Poly1305
- An agent is listed but inert until an operator approves it by name; a lapsed approval
  window is a no
- Packet capture and HTTPS interception cannot be ordered remotely

### Fixed

Each of these was found by looking at a real recording or a real plan, not at the code.

- Every process launch was reported as code injection. A new process's first thread is
  created by its launcher, so the cross-process rule fired on all of them — five critical
  findings in a session whose subject started five ordinary programs. Thread events with an
  unattributable process id were also reported, as `REMOTE THREAD Idle (0)`.
- The network view claimed the subject had contacted 84 hosts when it had contacted three:
  every flow on the machine was listed, not the subject's. Unattributed flows are now counted
  and declared rather than silently attributed or silently dropped.
- One HTTP fetch produced two connection records, one of which named the operator's own
  machine as the host contacted, and split the byte totals across both.
- Removal plans proposed deleting shared Windows state — the Background Activity Moderator,
  certificate stores created on demand by anything that checks a signature, group policy
  trees, and the TCP/IP service's configuration. 141 items became 12, all of them the
  subject's own. Protected-service rules had also been missing entirely because kernel events
  name `ControlSet001` while every rule names `CurrentControlSet`.
- The safety policy now runs at plan time as well as apply time: a plan listing items the
  runner will refuse describes something other than what will happen.

### Known limitations

- Kernel tracing requires an elevated process
- URLs are read from the Windows HTTP stacks; software bringing its own TLS is invisible to
  them unless HTTPS interception is enabled
- The causal tree bounds artifacts per group rather than virtualizing; a very large session
  is summarised rather than fully expanded
- Packages are not signed; the plan hash detects damage, not forgery
- x64 only; ARM64 builds from source

### Notes

Embedding removal payloads into the executable was tested and rejected: patching PE resources
into a .NET single-file bundle truncated a 67 MB host to 9.6 MB and corrupted it. Packages
ship as `.ctpkg` sidecars. See [PACKAGE-FORMAT.md](docs/PACKAGE-FORMAT.md).

[0.1.0]: https://github.com/CaYatur/CaYaTrace/releases/tag/v0.1.0
