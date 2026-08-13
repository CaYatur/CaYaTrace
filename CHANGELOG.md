# Changelog

All notable changes to CaYaTrace are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [0.5.4] — 2026-08-13

### Fixed

**The plan did not contain the program.** Its executable and the library beside it were
absent from the plan to remove it, while the recording had named both four different ways.
The footprint was built by reading the program's directory off the disk at plan time, which
works exactly once — on the machine that still holds the files, before anything has removed
them. On the session this was measured against, an antivirus had quarantined the executable
between the recording and the plan, so the directory listing returned two files and the two
that had done all the work were simply gone.

The recording is now the source and the disk is only ever an addition to it. Two signals
carry it:

- **Every module the program loaded that Windows does not own.** The strongest statement a
  recording makes about what a program consists of, and the only one that reaches a library
  side-loaded from somewhere it should not be. Measured: the subject's process tree loaded
  74 modules, 72 out of System32 and two out of its own directory.
- **Every file in its directory the recording shows being *used*** — loaded, read, written —
  as opposed to merely opened.

That last distinction matters more than it sounds. The DLL search order tries the
application's own directory first, so resolving imports produces an open for every Windows
library *inside the program's folder*, for files that do not exist and never did. A plan
built from opened paths lists a dozen of them, one of which is `cmd.exe` wearing a path
under the operator's profile that passes every check written to recognise a system location.
Thirteen were rejected on the session this was measured against, and the four real files
kept.

It is also now the same answer on every machine. Observations are tokenized when written, so
a session recorded under one profile and read under another had the footprint resolving to
`%USERSROOT%\<name>\…` against the recording's `%USERPROFILE%\…` — two strings that never
met.

**A folder now has to be earned.** Reading a program's directory finds what it shipped and
never touched — a licence, an unused plugin — which no recording can name. It also finds
everything else in there, and a program run straight out of a downloads folder has a
"directory" that belongs to the operator. So the proportion decides: when the program's own
files are most of what is in the folder, the rest goes with it and the folder is offered;
when they are a minority, nothing is taken but what the recording named. A proportion rather
than a file count, because the number of files a program ships has no useful bound.

**A locked file said "in use or locked" and stopped.** That tells an operator nothing they
can act on. The machine knows what is holding it, so it is now asked: the Restart Manager
names the processes with the file open, and most of the time that is the whole answer,
because most of the time it is a preview pane and closing it costs nothing.

When naming it is not enough, a second pass — asked for explicitly, never automatic —
climbs the rest: clear the attributes that are bookkeeping rather than protection, stop the
processes holding the file, take ownership where access is denied, and hand anything still
immovable to the session manager to move before anything else starts at the next restart.
Nothing on the ladder deletes; the restart-time operation moves the file into quarantine
exactly as the immediate path does, so a removal that finishes after a reboot is as
reversible as one that finishes straight away. Anything Windows marks critical is left
alone.

**A removal reported one line and showed its results only once it was over.** Every item now
carries its own live status as the run proceeds — waiting, working, removed, kept, at
restart, in the way — with what stood in the way written beside it, and an offer to try
harder on whatever is left.

- The rollback journal was an exclusive handle held for the runner's lifetime, so a second
  run against the same quarantine folder threw before doing anything. That is precisely the
  run that retries what the first could not finish.
- A folder that could not be removed said only that it was not empty. It now names what is
  still in it, which is the difference between a refusal and an explanation.
- Progress reports carry the plan item itself rather than a description of it, so several
  values under one registry key no longer collapse onto a single row.

### Also fixed

- **Remediation plan UI and state management:** plan building state transitions, clearing
  previous plan and remediation state when loading sessions or packages, plan table
  rendering, and error feedback.
- **Export package handling:** guarded when the plan came from an imported package, and made
  state consistent across plan re-evaluations.

## [0.5.3] — 2026-08-13

### Fixed

**The plan removed a program's registry footprint and left the program on disk.** Everything
in it came from watching the recording, so it could only ever contain what the subject
created *while being watched*. A subject is normally downloaded, unpacked and then recorded
— its own executable and the folder it unpacked into already existed, and no event names
them. Measured on a real session: two registry values, and not one of the executables that
had done all the work.

The program itself is now a candidate: its image, every image its process tree ran, and the
contents of the directory those sit in, whether or not the recording watched them appear.
Windows' own binaries never are — a batch file that launches `cmd.exe` has not made
`cmd.exe` its own, and being inside the subject's process tree does not transfer ownership
of a binary.

**Listed file by file.** Each file beside the executable is its own item. The directory is
offered only when everything in it belongs to the program, because a folder is a container
and a container can hold something the operator wants: a subject run out of Downloads must
never take Downloads with it, and one unpacked into its own folder should take the folder.

**The operator's own folders were still being offered.** The guard added in 0.5.2 compared
raw paths against the folders of the machine *reading* the session — so a session recorded
on one machine and read on another compared two different profiles and decided they were
different. It also only covered directory-create events, and opening a directory is
reported as a *file* create. Both fixed: the comparison is on the tokenised path, and the
guard covers both events.

**A hundred rows saying "protected — will not be touched".** A refusal was made visible in
0.5.0 by leaving it in the plan, which was the wrong place for it: one recording produced
107 registry keys under `SystemCertificates`, all Windows' own, all unremovable. They are
counted and reported now, not listed.

**The plan options could not be clicked.** They were disabled from a session flag, and the
state went stale. Two previous fixes did not hold, so the options are simply never disabled
— they are choices about what a future plan should contain, setting one before a session is
open costs nothing, and disabling them bought no safety.

### Changed

**Sample data from real investigations is anonymised throughout** — domains, addresses,
service names and file names in comments, tests and this file. A real indicator in a public
repository is both a disclosure and a pointer back to what is being investigated. The
measurements stay; the identifiers do not.

## [0.5.2] — 2026-08-13

### Fixed

**The Remediate view said no session was loaded when one was.** The build button and the
three plan options are enabled from the loaded session, and nothing re-evaluated that when
the view was opened — so an operator who had just finished a recording arrived at a view
telling them no session existed, with every option greyed out and no way to build a plan
at all. It is re-evaluated on entry now.

**The plan offered to delete the operator's own folders.** The kernel reports a directory
create when a program *opens* a directory with a create disposition, which is what every
program does to a folder it is about to read — indistinguishable from actually making one.
So a program that merely looked inside Documents produced an event reading "created by",
and Documents appeared in the plan, ticked, along with the profile root, the desktop, and
the Internet cache.

Folders Windows maintains are no longer candidates, resolved from the running machine
rather than matched against a list of names — a profile can be redirected to another
drive, and a name comparison would miss it in exactly the case where deleting it costs the
most. A directory the program genuinely created is still offered.

### Changed

**Sample data taken from a real investigation is anonymised throughout.** Domains,
addresses, service names and file names from the operator's own sessions had been written
into comments, tests and the changelog. A real indicator in a public repository is both a
disclosure and a pointer back to the thing being investigated. The measurements stay — the
counts and the shapes are what make a comment worth reading — and the identifiers are
replaced.

## [0.5.1] — 2026-08-13

### Fixed

**A system-wide recording produced a removal plan of almost nothing.** Scope is marked
relative to a root process and a system-wide recording has none, so no process was ever
in scope, every observation carrying an actor was discarded, and the only survivors were
the handful that carry none. Measured on a real recording of an installer: 759,179 file
operations and 1,048,112 registry operations went in and **two items** came out.

Scope cannot be the filter when there is no subject. What replaces it is the signature of
whatever made the change: Windows is busy during any recording — Delivery Optimization
counters, Explorer's pane state, Defender's timestamps — and every one of those is written
by something Microsoft signed, while nothing a third-party installer drops is. The
machine's own housekeeping is excluded by who did it rather than by where it landed, which
needs no list of paths to maintain and cannot accidentally exclude a program that installs
itself somewhere unusual.

The same recording now yields **1,264 items** — 536 individual files, 351 registry values,
375 keys — including the subject registering itself under `SafeBoot\Minimal`, which is how
a program arranges to keep running in Safe Mode and was previously absent from the plan
entirely.

## [0.5.0] — 2026-08-13

### Added

**The contents of HTTP requests and responses.** The requests table showed a method, a URL
and a size; the headers and the body were in the session the whole time with nothing to
open them. A row now expands to show every header it carried and a button for the body — so
a POST that uploaded 45 bytes shows the 45 bytes. They travel with an exported report too.

**A sweep for what a program left behind.** The removal plan is built from the recording:
every item in it is something the tool watched being created. That is the right foundation
and it is not the whole answer, which is why removal was skipping things — anything
installed before the recording started, or dropped by an installer that ran outside the
traced scope, was never observed and so was never removed.

The sweep asks the opposite question: what on this machine is named after it. Four depths,
because how hard to look is the operator's choice and each one matches more loosely:

- **None** — only what was recorded, as before.
- **Safe** — directories and registry keys named after the program.
- **Moderate** — also uninstall entries, services, App Paths, startup values and scheduled
  tasks, matched on the names a person would recognise rather than on a GUID.
- **Advanced** — also registry values anywhere under the software hives whose *data* points
  at one of its directories. Slow, bounded, and it says when it stopped early.

Nothing here deletes. It produces candidates with the reason each one matched, every one
still passes the safety policy, and the operator approves the plan — a sweep that matched
too widely is a list to uncheck rather than damage, which is the only way an aggressive
search is safe to offer. The words being searched for are shown, so an unexpected match is
explainable, and a name with nothing distinctive in it produces no sweep rather than a
sweep of the whole machine.

### Changed

**A refused item stays in the plan, marked.** It used to be dropped, so an operator
comparing the plan against what was still on their machine could not tell the difference
between something the tool had not found and something it had decided not to touch. The
first is a gap to report; the second is a judgement to argue with. The runner still refuses
it — this changes what the plan says, not what it does.

## [0.4.2] — 2026-08-13

Found by an operator who could see that a program had talked to something and not what it
had said. Three defects between the capture and the report, all of them in the part that
turns bytes into an answer.

### Fixed

**Conversations were reported backwards.** The two halves of a conversation are held by
whoever opened it — forward from the initiator, reverse back to them — while the key that
files them is ordered by sorting the two endpoints. Those are unrelated facts, and the code
picked between the halves using the sort. Where the two happened to agree the answer came
out right; where they did not, the report said the subject had sent what it had received.

Measured on a real capture: a program's twenty-one connections to one address each reported
29,940 bytes sent and 5,076 received, when it had sent 5,076 and received 29,940. The bytes
filed as "sent" opened with a ServerHello — a message no client ever sends, and the tell
that the halves were swapped.

**Which meant the server name was usually missing.** The name a program asks for lives in
the client hello, so a swapped conversation had the handshake in the half nothing looked at.
Both halves are now tried, which also covers a capture that began after the connection did.
On the same capture the number of conversations carrying a name went from 138 to 159 — and
one of the new ones turned `x.x.x.x`, which says nothing, into `example.com`, which says
everything.

**Exported reports carried byte counts and no bytes.** Contents were attached only at the
full scope, so a default export left every "what was sent" button disabled: an operator
could see that a program sent 6.6 KB to an address and had no way to find out what was in
it. They now travel with every export except the deliberately cut-down one, since volume is
what the scopes are for and contents are the reason a conversation is recorded at all.

### Changed

**Said plainly why a conversation on this machine has no contents**, having established it
rather than assumed it. The Winsock provider hands over a kernel address, not the caller's
buffer, so reading the sending process's memory does not reach it and no privilege changes
that. Established loopback traffic never becomes a packet either — capturing every
component produced 5,276 events and not one of them loopback; the only loopback packets that
appear are ones to a closed port, which take the ordinary route in order to be rejected.
What is left would be a kernel driver or injecting into the subject, and neither belongs
here.

## [0.4.1] — 2026-08-13

### Fixed

**The chat answered nothing in 0.4.0.** Every reply carries a `web` field holding the
lookup findings, normally an empty array. The page's chat handler used
`payload.web !== undefined` as the acknowledgement for the web-lookup toggle — and an empty
array is not undefined, so every answer matched that branch, ticked the checkbox and
returned before the reply was rendered or the spinner stopped. Asking anything produced a
spinner that never finished.

The control message now has a name of its own. A test reads both sides — the page's
dispatch and the host's reply — and fails if a field can ever mean both, because no test
that drives the assistant can catch this: the harness calls it directly and never crosses
the bridge, which is exactly why it shipped.

**Web lookups had never been called.** The feature went out with no execution path ever
having run: the search parsing keys on class names somebody else controls, and if they had
moved it would have returned nothing while reporting nothing — the same shape of failure
this release was spent removing from HTTPS interception. There is now a test that performs
a real search, and one that pins the refusals: nothing leaves the machine until the
operator switches it on, and a private or non-web address is never fetched, because a name
out of a recorded session was chosen by whatever was being recorded.

**Page fetching was unreachable.** Search snippets are two lines of marketing and rarely
say what a file is; the top result's own page usually does, and is now retrieved and used
in place of the snippet.

## [0.4.0] — 2026-08-13

Two features that had never worked, found by running the shipping binary instead of
reading it, and an assistant rebuilt around a transcript of somebody using the old one.

### Fixed

**HTTPS interception had never once worked.** A session with it enabled reported zero
exchanges, zero failed connections and no explanation — which reads exactly like a program
that made no requests. Three faults were stacked on top of each other and a bare `catch`
at the top of the accept loop kept all three off the screen:

- Traffic never reached the proxy. Writing the registry does not move a process already
  running — WinINet caches the setting until told to re-read it, and WinHTTP never consults
  that key at all, so services, installers and updaters went straight out. Both are now
  configured, WinHTTP through its own API rather than `netsh`, because spawning a process
  mid-recording puts the tool into its own evidence.
- Every TLS connection then threw before a byte moved. A leaf certificate was minted at
  "now plus twelve hours" while its authority had been created earlier with the same
  lifetime, so the leaf always outlived its issuer and certificate creation refused it
  outright — from the very first connection, for the whole life of the feature.
- The certificate that then built was one Schannel will not accept as a server credential,
  because its key was ephemeral. It failed as a `Win32Exception`, which is neither of the
  two exception types the handler caught, so it escaped as well.

Both catches now report instead of swallowing. That is the actual repair — the certificates
were only bugs, and a bug that cannot be seen is the part that lasts.

**The proxy setting could be left behind for good.** It lived in a field, so a clean stop
restored it and anything else did not — and anything else is the expected case when the
thing being recorded fights back. What it left was a machine configured to reach the
network through a port nobody is listening on: every browser, updater and installer fails,
with errors that name no cause, and unlike the certificate it never expires. The previous
configuration is now written to disk *before* it is changed and undone on the next launch
whatever that launch was asked to do. It only undoes its own change; a proxy the operator
set themselves afterwards is left alone.

**A scoped session could contain other programs' traffic.** With interception on, the
system proxy is machine-wide and every program's requests arrive. Ownership was resolved
from the connection table with a throttle that allowed one lookup per second, so the first
connection in any burst got an answer and the rest were attributed to nobody — and
unattributed traffic was kept. Measured, on a session recording one PowerShell script: the
operator's desktop-app telemetry with a key in the query string, their GitHub API calls,
and their editor's API traffic. Windows is now asked who owns the port whether or not the
session recognises the answer, and a process the session has never seen is not a failure to
attribute — it is somebody else's.

**Every local conversation reported twice the bytes it carried.** The Winsock send path is
nested: the API is entered, an inner path is entered, both return. Counting exits counted
each send twice, while a receive is a single pair and was right. A probe sending exactly
three buffers of ten bytes reported six sends of sixty; it now reports three of thirty,
from both ends.

**The build workflow failed on a missing file rather than a failing test.** The repository
declares x64 and ARM64 platforms, so building the solution writes `bin/x64/Release` while
testing the project on its own falls back to AnyCPU and reads `bin/Release`.

### Changed

**The assistant follows a conversation and answers about what was asked.** From a
transcript of real use: asked whether anything connected to one host it returned five,
including Windows' own connectivity checks; asked which were suspicious it said all five;
asked which was more critical it said it did not recognise the question; asked whether
programs had talked to each other locally it answered no and listed the same five internet
hosts; asked which programs opened it returned seventy-three listening sockets; asked how
to remove the suspicious services it produced instructions to delete Network Location
Awareness and reset the network adapter.

- The last few exchanges are remembered, so "which of those", "only the relevant one" and
  "write that as one line" mean something. Clearing it is one click.
- What a question names is extracted and the answer narrowed to it, matched against the
  names the session holds — no pattern matches a service called `a1b2c3d4e5f60718`, and
  pasting one is the shortest way to ask about it. A name the session never saw is answered
  as absent rather than with everything else.
- Topic matching required a word boundary. "hangi programlar açıldı" matched the listener
  keyword "aç" inside "açıldı"; Turkish suffixes mean only the start can be anchored.
- Conversations between programs on one machine have their own question, which is why the
  old one answered "no" while the Winsock records said otherwise.
- The model may now compare, rank and say what something resembles, and must mark that as
  its reading. Three things stay out of its hands: which records an answer covers, which of
  them the tool considers suspicious, and any command the operator might run.

**Commands are built from the session, never written by a model.** For one named thing,
gated on the analyzer's own verdict — which is what would have stopped the advice to delete
`NlaSvc`, since the scoring already found nothing remarkable about it. A service is stopped
before its image is deleted, the executable is parsed out of the command line rather than
passed whole, and a driver registered by a relative path produces no delete at all.

### Added

**Web lookups for the assistant, off unless switched on.** Searching for a file name
publishes it, and a name from a real intrusion is itself sensitive — that is the operator's
disclosure to make. Names, hashes and domains only; results are labelled as somebody's
claim rather than as evidence, and styled so the two cannot be confused.

**A harness that replays a real transcript against a real session and a real model**, so
the next assistant regression is found the way this one was.

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
