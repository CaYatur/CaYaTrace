# CaYaTrace architecture

CaYaTrace answers one question as completely as Windows allows:

> **What did this program actually do to my machine, and to the network?**

Everything below serves that, and the design decisions are recorded with the reasoning
that produced them — including the ones that were settled by measurement rather than
preference.

---

## 1. The constraint that shapes everything: no kernel driver

Sysmon-class visibility comes from a signed minifilter driver. Shipping one requires an
EV code-signing certificate plus Microsoft attestation signing through Partner Center.
For an open-source, portable tool that is not viable — and a driver that users must
install by enabling test-signing mode is worse than no driver at all.

So the engine is **ETW-based**. This gets most of the depth with no install, no reboot,
and no permanent change to the machine. What it costs is stated plainly in
[§7 Known limits](#7-known-limits) rather than hidden.

`ICollector` is the seam. A driver-backed collector can be added later without touching
correlation, storage, analysis, or the UI.

---

## 2. Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CaYaTrace.App        single executable · workbench · CLI · agent · remediator │
├──────────────────────────────────────────────────────────────────────────┤
│  Export        │  Analysis       │  Remediation    │  Fleet              │
│  HTML/JSON/CSV │  templating     │  planner        │  host ↔ VM agents   │
│  per-category  │  multi-VM merge │  safety policy  │  encrypted channel  │
│                │  VT · Ollama    │  quarantine     │                     │
├──────────────────────────────────────────────────────────────────────────┤
│  CaYaTrace.Collectors    kernel ETW · user ETW · snapshots · network      │
├──────────────────────────────────────────────────────────────────────────┤
│  CaYaTrace.Storage       SQLite (WAL) + append-only JSONL journal         │
├──────────────────────────────────────────────────────────────────────────┤
│  CaYaTrace.Core          identity · correlation · naming · causal graph   │
└──────────────────────────────────────────────────────────────────────────┘
```

`Core` has no dependency on ETW, on SQLite, or on Windows-specific tracing. That is what
makes the correlation logic unit-testable without administrator rights, and it is why the
identity tests run in CI.

---

## 3. The correlation layer is the product

A monitor that records events but attributes them wrongly is worse than no monitor: it
produces confident, false conclusions. Four identity maps carry that weight.

### 3.1 Process identity — never the raw PID

Windows recycles PIDs aggressively. A busy installer run burns the same PID several times.
Keying a tree on a raw PID silently merges unrelated subtrees.

`ProcessKey` prefers the kernel's **process start key** (`UniqueProcessKey` on the kernel
process provider), which is monotonic and never reused for the life of a boot. Where it is
unavailable it falls back to `(PID, creation time)`.

`ProcessTable` keeps every **generation** of each PID, ordered by start time, so an event at
time *T* resolves to the process that was alive at *T*.

**Scope adoption.** Windows deliberately breaks causality in several places: a service
started through the SCM parents to `services.exe`, a COM activation to `svchost.exe` or
`dllhost.exe`, a scheduled task to the task engine. Without adoption those processes — often
the interesting ones — fall outside the tree. `ProcessTable.Adopt` re-parents them with a
recorded reason, which appears in the UI as `adopted:service-start` rather than being
silently invisible.

### 3.2 FileObject → path

Kernel file events carry a pointer, not a name. The name was announced once, on create or
during rundown. Two pointers matter and both are tracked: **FileObject** (per-handle,
released on cleanup so a recycled pointer cannot inherit a stale name) and **FileKey**
(per-file-control-block, shared across handles, announced by rundown).

Lose those announcements and the tool reports *"wrote 4096 bytes to 0xFFFFCE0812A43B90"*.

### 3.3 KCB → registry path

The same problem, worse. Registry events carry a key-control-block pointer plus a name
*relative to it*. The full path only exists if `KCBCreate` and the session-start rundown were
tracked. This is the step most naive ETW registry monitors skip, and it is why their output
is unusable.

### 3.4 5-tuple → process

Three sources know different halves of the network story:

| Source | Knows the process | Knows the content |
|---|---|---|
| Kernel network events | yes, directly | no |
| Packet capture (Pktmon/WFP) | **no** | yes, bytes |
| Intercepting proxy | no — only a local socket | yes, full HTTP |

`FlowTable` joins them on the 5-tuple plus a time window, and **preserves how good each join
was** (`Direct`, `Probable`, `Weak`, `None`) rather than flattening it. Packets that match no
known flow stay unattributed instead of being guessed onto a plausible process.

The proxy case deserves note: the proxy sees only `127.0.0.1:<ephemeral>`, so the ephemeral
port is the entire link back to the real client. Port ownership is polled and time-bounded,
because a short-lived socket can open and close between two polls.

---

## 4. Evidence sources, and why provenance is first-class

| Source | Attribution | Catches | Misses |
|---|---|---|---|
| Kernel ETW | direct | file, registry, process, module, network | anything lost to buffer pressure |
| User-mode ETW | direct | DNS, WinINet/WinHTTP URLs, TLS metadata | apps with their own TLS stack |
| Snapshot diff | **none** | persistence set up through APIs that emit no useful event | who did it |
| Packet capture | by 5-tuple | every byte on the wire | encrypted payload |
| Proxy (opt-in) | by local port | full request/response bodies | pinned certs, ECH |

Every `Observation` records its `EvidenceSource` and `AttributionConfidence`. An analyst must
be able to tell a directly observed kernel event from something inferred by diffing two
snapshots, because the two carry very different evidentiary weight.

Snapshot-derived changes start unattributed and are only linked to a process when a live
kernel event touched the same artifact. When no such event exists they stay unattributed —
which is actionable — rather than being attributed to whatever seems likely, which is not.

---

## 5. Data quality is reported, never hidden

Enabling kernel file and registry keywords machine-wide produces tens of thousands of events
per second during an install. When ETW buffers fill, events are dropped **silently**. If a
dropped event happens to be a `KCBCreate` or a file rundown, every later operation on that
object becomes unresolvable.

The failure mode is insidious: the tool then shows a *smaller, cleaner-looking* tree that is
simply missing things. An analyst who does not know this concludes the program did less than
it did.

So the session header, every export, and the CLI's exit path all carry:

- `EventsLost` / `BuffersLost` straight from the ETW session
- events dropped by our own ring buffer when storage fell behind
- file-name and registry-name resolution hit rates
- unattributed network flows
- collectors that failed or were skipped for lack of privilege

Default ETW buffer pool is **256 MB**, deliberately large. Memory is cheaper than a session
that quietly under-reports.

### The write path

Nothing on a collection thread touches SQLite. ETW delivers on a dedicated processing thread
per session; any stall there causes the kernel to fill buffers and discard events across
*every* provider at once. Collectors do a non-blocking enqueue; a background writer batches
into WAL transactions.

When the queue fills, the sink **drops and counts** rather than applying back-pressure.
Blocking would convert a storage stall into kernel-level event loss, which is strictly worse.

An append-only `raw-events.jsonl` is written alongside, so a hard kill — including one caused
by whatever is being analysed — still leaves usable evidence.

---

## 6. Session lifecycle

Ordering is load-bearing:

1. **Baseline snapshot** — before collectors and before the subject, so the inventory is not
   polluted by our own activity.
2. **Seed registry values** from that baseline, so the *first* write to a value reads as a
   transition (`0 → 1`) instead of an establishment. Without this, most of an installer's
   registry activity would show no "before".
3. **Create the subject suspended.** Between "process started" and "ETW delivering events"
   there is typically 50–300 ms. Installers unpack in that window; droppers write and execute
   their payload in it.
4. **Start collectors**, wait for providers to install.
5. **Resume the subject.**
6. On stop: after-snapshot → diff → attribute → persist correlation tables → checkpoint.

---

## 7. Known limits

Stated plainly, because a forensics tool that overstates its coverage is dangerous.

- **No kernel driver.** No pre-operation callbacks, no blocking, no guaranteed delivery.
- **Registry value data is recovered by reading the value back**, not from the event — ETW
  does not carry it. The read is rate-limited so it cannot stall the callback thread, and the
  "before" value comes from the baseline or from an earlier in-session observation. When
  neither exists, `OldValue` is null rather than invented.
- **Encrypted traffic stays encrypted** without the opt-in proxy. Certificate pinning, ECH,
  and custom trust stores are not bypassed — CaYaTrace does not implement evasion of
  application security controls.
- **Anti-analysis is not defeated.** VM detection is *reported* so an analyst can compare a VM
  run against bare metal; it is not hidden.
- **Snapshot diffs prove a change happened, not who made it.**

---

## 8. Remediation safety

A tool that deletes files and registry keys on a third machine, from data recorded elsewhere,
can brick that machine. Five properties are structural, not configurable:

1. **A non-overridable deny list.** Windows-owned paths, boot-critical registry subtrees, core
   services, and shared containers can never appear in a plan. There is no force flag — an
   uninstaller that can be talked into deleting `System32` is a wiper with extra steps.
2. **Fingerprint re-verification.** The same path on a different machine may hold an unrelated
   file. Items whose live hash, value data, or command line contradicts the recording are
   skipped and reported.
3. **Quarantine, never delete.** Files move; registry keys are exported to `.reg` first.
4. **A rollback journal written as it goes**, so an interrupted run is still reversible.
5. **Dry run is the default.** Producing a plan and applying it are separate decisions.

The planner is conservative in the same spirit: it proposes only artifacts the subject
*brought into existence*, never things it merely touched, and cancels creations the subject
later removed itself.

---

## 9. Packaging

One executable, several modes, selected by argument or by a sidecar package beside it.

**Payloads are not embedded into the executable.** This was tested, not assumed: patching a
payload into a .NET single-file bundle's PE resources via
`BeginUpdateResource`/`UpdateResource`/`EndUpdateResource` **truncated a 67 MB published host
to 9.6 MB** and it then failed to launch with *"Failure processing application bundle;
possible file corruption."*

A sidecar is also the better security posture: an exported remediator is carried onto a
possibly-infected machine, and a self-copying, self-appending executable is exactly the
behavior endpoint protection reacts to. See [PACKAGE-FORMAT.md](PACKAGE-FORMAT.md).

Build flags that matter:

- **Trimming is disabled solution-wide.** TraceEvent uses reflection and ships native
  components; trimming silently breaks manifest-based provider parsing at runtime.
- `IncludeNativeLibrariesForSelfExtract=true`.
- The WebView2 user-data folder is set explicitly to LocalAppData — the default writes beside
  the executable, which fails on read-only or removable media and breaks the portable story.

---

## 10. Fleet (designed, not yet implemented)

Multi-VM comparison exists because the same sample writes different filenames and partially
different paths on each machine. That needs **path templating**, not a diff: tokenize into
(known-folder, segment pattern), flag high-entropy segments as variable slots, emit a
template with variables. The template is what makes a package portable to a third machine.

Transport requirements, deliberately not stubbed with something weaker in the meantime:

- The agent stays **inert until an approved host connects**. Launching it does not start
  collection or open a channel.
- Enrollment is by one-time pairing code; the host approves each agent explicitly.
- The channel is authenticated and encrypted at the application layer (X25519 key agreement,
  ChaCha20-Poly1305 framing) rather than relying on TLS, because a lab network frequently has
  no usable PKI and self-signed TLS between VMs adds trust-store changes on machines that are
  meant to be disposable.

A half-built remote-collection channel on an analysis network is a liability, not a feature.

---

## 11. Why a web UI in a native shell

Three reasons specific to this product: the causal tree is a deeply nested, heavily
virtualized view that HTML handles better than any XAML control; the self-contained HTML
export is then the *same* rendering code rather than a second implementation that drifts; and
the CaYaDev visual language is already expressed in CSS.

Design tokens are taken from `cayadev.com` directly — `#dc2626` primary, `#111826` background,
`#182438` cards, Inter for text and Consolas for the terminal surfaces — so the tool looks
like the rest of the product line rather than approximating it.
