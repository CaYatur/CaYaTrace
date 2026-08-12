# Roadmap

Ordered by what unblocks the most, not by what demos best. Each item states why it sits where
it does.

## 0.1 — engine and remediation ✅

The correlation layer, storage, kernel tracing, snapshots, removal planning, and the CLI.
Built first because every later feature is a consumer of it: an analysis pass, a UI, or an
export is only as correct as the attribution underneath it.

## 0.2 — the workbench ✅

The WebView2 UI over the existing engine, in the CaYaDev visual language. Everything the
engine can do is now reachable from the window: recording, past sessions, findings, the
causal tree, network activity, comparison, the local model, removal, and the fleet.

- Causal tree, category filters, full-text search over targets
- Session data-quality panel, prominent rather than tucked away
- Removal plan review with per-item approval before anything is applied
- EN/TR throughout, following the Windows display language

Still open: timeline scrubbing, and virtualization for the tree — an installer run produces
six figures of nodes and the tree currently bounds the count per group instead.

## 0.3 — the network layer ✅

The half the tree is currently missing. Layered so the invasive part stays optional:

1. **DNS and TLS metadata** — query/answer pairs from the DNS client provider, SNI, ALPN,
   and JA3/JA4 from the TLS handshake. No trust-store change, works for every application.
   This is what turns raw IPs in the tree into `api.example.com`.
2. **URL capture from WinINet and WinHTTP** — full URLs for the large share of Windows
   software using the platform HTTP stacks, still with no CA involved.
3. **Packet capture via Pktmon** — bytes on the wire without Npcap, attributed by 5-tuple.
4. **Intercepting proxy (opt-in)** — full request and response bodies. Per-session CA,
   removed on exit and re-checked on next launch. See [SECURITY.md](../SECURITY.md).

## 0.4 — analysis ✅

- **Path templating.** The prerequisite for multi-VM work: tokenize paths into
  (known-folder, segment pattern) and flag high-entropy segments as variable slots, so
  `%APPDATA%\a8f3c1\svc.exe` and `%APPDATA%\d92b47\svc.exe` unify into one template. Diffing
  two JSON files does not do this, and without it a package built from VM observations does
  not port.
- **Multi-observation merge** — artifacts seen on every machine versus once
- **Risk scoring** with visible reasons, never an opaque number
- **VirusTotal** — hash lookups first; upload only on explicit per-file consent, since
  uploading a sample discloses it
- **Ollama** — local model analysis over a selected subset of session data, with the prompt
  shown before it is sent

## 0.5 — export ✅

- Per-category selection, minimal / standard / full presets
- Self-contained HTML report for readers who will not use the tool — the workbench markup
  with the data inlined, so the report is the view rather than a second renderer
- CSV with spreadsheet-formula neutralisation, JSON for the whole session
- Still open: a redaction pass for sharing evidence outside the machine it came from

## 0.6 — fleet ✅

Multi-VM collection. Deliberately last among the major features: it is the largest new attack
surface in the project, and it is worth building only once path templating makes the combined
data genuinely more useful than reading two sessions side by side.

- Agent **inert until an approved host connects** — launching it starts nothing
- One-time pairing code enrollment, explicit host-side approval per agent
- Application-layer encryption (ephemeral ECDH P-256 + HKDF + ChaCha20-Poly1305), because a
  lab network usually has no usable PKI and self-signed TLS means trust-store changes on
  machines meant to be disposable. X25519 was specified first and dropped: it is not
  reachable through Windows CNG on .NET 8, which was measured rather than assumed.
- Packet capture and HTTPS interception are absent from the order type by design — a host
  able to trigger them turns a paired agent into a remote administration channel
- Still open: transports other than TCP, for setups where that is blocked

## Later

- Scrubbing along the timeline, and a virtualized tree. The timeline itself landed in
  0.2.0; what is still missing is dragging a window across it and seeing the rest of the
  views follow.
- Contents of loopback conversations. They are visible as connections, but the Windows
  packet monitor observes network adapters and traffic that never leaves the machine does
  not cross one. The intercepting proxy covers local HTTP; anything else would need a
  different capture path.
- Redaction pass before sharing a session
- Comparison results shown in the workbench alongside the CLI output
- ARM64 release binaries
- Optional signed kernel driver for pre-operation visibility, if attestation signing becomes
  reachable. The `ICollector` seam exists so this does not require rework.
- Sigma / YARA rule matching over recorded sessions
- Comparison view: diff two sessions of the same program across versions

## Deliberately out of scope

These are not "not yet" — they are decisions.

- **Defeating anti-analysis.** VM detection is reported so an analyst can compare a VM run
  against bare metal. It is not hidden.
- **Bypassing certificate pinning, ECH, or custom trust stores.** Defeating an application's
  security controls is an evasion capability, not an analysis one.
- **Blocking or containment.** CaYaTrace observes and remediates after the fact. It is not a
  sandbox and not an EDR, and presenting it as either would be dangerous.
- **A force flag for the remediation deny list.** An uninstaller that can be talked into
  deleting `System32` is a wiper with extra steps.
