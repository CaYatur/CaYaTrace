# Changelog

All notable changes to CaYaTrace are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-08-13

Everything here came from someone using 0.2.0 and reporting what did not work.

### Added

**Conversations between processes on one machine.** A subject opened four connections to
`127.0.0.1` and the network view showed four rows of `0 B` — no contents, no peer, nothing
to conclude from. There was nothing to fix in the packet path: the Windows packet monitor
observes network adapters and loopback traffic crosses none of them.

Winsock does see it. A new collector on the Ancillary Function Driver reports, for
conversations that never leave the machine: the process, the socket, both addresses, bytes
each way, sends and receives, and the program at the other end. Pairing works from either
side, and ports already being listened on when recording starts are read from the
connection table, because a service that came up at boot emits no bind event to observe.
It does not report the bytes, and says so — the provider carries a pointer into the
sending process, not a copy, and following it would mean reading another process's memory
while it runs.

**Assistant controls.** The chat has its own model picker with "no model" first, and a stop
button.

### Fixed

- **The assistant hung whenever a model was configured.** `GenerateAsync` takes an `object`
  in third position, so passing a cancellation token there compiled, boxed the token into
  the response-format field, and left the real token defaulted — the request could not be
  cancelled and its own timeout never fired.
- **The exported report offered HTML and Text and wrote JSON for both.** It now produces
  what was asked for, including a copy of itself for HTML.
- **The save dialog appeared to be writing an executable.** A session recorded from
  `Setup.exe` is named after it, so the suggested name was `Setup.exe.html` — and Windows
  hides the last known extension.
- **Conversation contents were unreachable in an exported report.** The bodies lived in the
  session database and the report has no engine behind it; a bounded preview now travels
  with the report at full depth.
- **Remediate was disabled until a session was loaded**, which made the one workflow
  packages exist for — carrying one to a machine that has never recorded anything —
  unreachable from the window.
- **A recording reported 59.7% of registry operations unresolved while every change had
  been named.** Reads were resolved-or-discarded on the spot and counted against the same
  figure. They are parked and re-resolved like everything else now, dropped before changes
  are when memory runs short, and measured separately — so the figure answers "is the
  evidence complete" rather than "how much of everything the machine did could be named".

## [0.2.0] — 2026-08-12

Recorded the same installer with two other tools at the same time, on the same machine,
and compared what each of them said. Almost everything below came out of that comparison
or out of running the result — the evidence was already being collected and nothing was
reading it.

### Added

**Persistence** — a view, and a model behind it. Every way a program arranged to run
again, one entry per mechanism rather than one per registry value, carrying what it
configured: image path, display name, start type, delayed start, account, and its recovery
actions decoded into words. Covers services, drivers, scheduled tasks, run keys, startup
folders, logon hooks, launch hijacking, AppInit and AppCert DLLs, boot execution,
authentication packages, security providers, netsh helpers, print monitors, time
providers, Winsock providers, COM servers, shell extensions, browser add-ons, Active
Setup, group policy scripts and command-prompt autorun.

**Timeline** — what ran, in order, for how long, under which parent, with what command
line, and what each one touched. It says plainly that Windows will not report which
process closed another without a kernel driver, rather than guessing from timing.

**Conversations** — the contents of what crossed the wire, reassembled from the packet
capture and grouped by whether the peer is on this machine, on the local network, or on
the internet. The local-network grouping is the point: a program talking to a peer or to
its own second copy appears in no firewall log, no proxy and no HTTP stack. Bodies are
stored content-addressed and opened on demand.

**Ask the session** — the assistant answers questions about what was recorded. Answers
are computed from the session; a local model, when one is configured, only rewords them,
is never asked to find anything, and cannot introduce a fact. Both are shown separately.
With no model the answers still work.

**Removal, finished** — progress while it runs, what fought it, and what to do with what
was quarantined: keep, put back, or delete for good. Anything configured to restart itself
is disarmed first — recovery actions cleared, autostart set to manual, watchdog groups
stopped together — because a removal running while its subject puts itself back looks like
it worked. Packages can now be opened and applied from the window.

**Fleet, both halves** — a machine can join a fleet from the window instead of only from a
terminal. Each connected machine gets its own panel with a live sample of what it is
doing, its process list, and the ability to stop a process, its children, or a service.
That is bounded on the agent side: it refuses anything the kernel marks critical and
re-checks every process id before acting. Recording options are chosen per run, and a
finished agent stays connected so a second recording does not mean re-pairing a machine
that was already trusted.

Also: an option to see what a path token stands for on the machine that recorded it, and
the workbench lets go of its console rather than hiding it — so software that kills
console hosts cannot take a recording with it, and starting the tool from a terminal no
longer hides the operator's own window.

### Fixed

Each of these was found by reading real output, not by reading code.

- **A transferred session lost everything that made it readable.** 106,311 observations
  arrived with zero processes and zero flows, because the agent streamed only
  observations. The whole causal tree hung under one "(unattributed)" root, the network
  view was empty, and nothing could be tied to the subject.
- **61 critical "code injection" findings, every one Windows acting on Windows.** The
  judgment moved out of the collector — where signatures are not yet verified and a
  discard is permanent — into the scorer, and the trust test is the code signature rather
  than the path, because software that wants to look like Windows installs itself inside
  the Windows directory.
- **1,864 of 2,000 findings were Windows Update.** Suppressed only when Microsoft signed
  the writer, so an unknown binary in the update cache is still one of the loudest things
  the scorer can say, and capped per category so no one category can fill the list again.
- **33,467 registry observations produced no registry findings at all**, while a
  comparison tool reported both installed services with their full configuration from the
  same machine.
- **A system-wide recording reported zero findings.** There is no subject in one, so
  nothing is in scope, and narrowing to the subject narrowed to nothing.
- **The plan and the analysis disagreed about what had been installed.** A program does
  not install a service, it asks the service control manager to — so the change belongs to
  another process and scoping to the subject's tree discarded exactly the artifacts that
  mattered most.
- **One service was reported twice and one task three times**, because the kernel, the
  inventory, the registry key and the tree entry each spell the same thing differently.
- **A scheduled task reported what it is called and never what it runs**, because the
  registry holds its actions as a binary blob.
- **Every reassembled conversation named the recording machine as the host contacted.**
  The canonical flow key orders its endpoints for accumulation, not by which end is local.
- **Quarantine listed nothing after moving three files**, because the reader was written
  against an invented journal schema rather than the one the runner writes.
- **Removal plans proposed certificate stores and shell state.** The crypto API creates a
  store wherever a component asks for one, so the shape is the rule, not the parent; and
  Desktop and Documents disappearing from Explorer's sidebar after a removal is worth
  refusing a whole class over.
- **`FailureActions` decoded wrongly.** The header is five fields, not four, and the action
  count routinely overstates. Verified against `sc qfailure` rather than documentation.
- Long paths pushed the whole page sideways and clipped every card; the tool reported its
  own tracing buffers as findings; and a startup entry appeared twice in a plan.

### Notes

Loopback conversations are seen as connections but their contents are not captured: the
Windows packet monitor observes network adapters, and traffic that never leaves the
machine does not cross one. Use the intercepting proxy for local HTTP.

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

[0.3.0]: https://github.com/CaYatur/CaYaTrace/releases/tag/v0.3.0
[0.2.0]: https://github.com/CaYatur/CaYaTrace/releases/tag/v0.2.0
[0.1.0]: https://github.com/CaYatur/CaYaTrace/releases/tag/v0.1.0
