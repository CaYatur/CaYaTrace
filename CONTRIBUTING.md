# Contributing

Thanks for looking. CaYaTrace is a forensics tool, so a few conventions here exist for
reasons beyond taste.

## Getting set up

```bash
git clone https://github.com/CaYatur/CaYaTrace.git
cd CaYaTrace
dotnet test
dotnet build
```

Requires the .NET 8 SDK on Windows. `dotnet test` needs no elevation — the correlation layer
is deliberately free of ETW and SQLite dependencies so it stays testable.

## The rules that are not negotiable

**Never commit captured data.** Sessions contain credentials, tokens, and personal data.
`.gitignore` covers `sessions/`, `logs/`, `*.ctpkg`, `*.etl`, `*.pcapng`. Do not work around
it. If a bug needs a session to reproduce, redact it or share it privately.

**Never block an ETW callback thread.** Anything inside a collector callback must be an
in-memory operation plus a non-blocking enqueue. A stall there makes the kernel discard
events across every provider at once, and those losses are silent. No I/O, no locks held
across work, no synchronous network calls.

**Never widen the remediation deny list at runtime.** No force flag, no config override, no
"advanced mode". If a legitimate case is blocked, the answer is a narrower rule reviewed in a
PR — not an escape hatch.

**Never invent attribution.** If a process cannot be determined, the observation stays
unattributed. `AttributionConfidence.None` is a useful answer; a plausible guess presented as
fact is not.

## Comments

Comment on **why**, not what. The code says what it does.

The valuable comments in this codebase explain a non-obvious constraint: why PID cannot be an
identity, why a name map must be bounded, why a payload is a sidecar rather than embedded.
Those save the next person a day of investigation. `// increment the counter` does not.

If you worked out something the hard way — from a spec, an experiment, or a failure — write
that down where the code depends on it.

## Tests

Correlation logic needs a test. That layer is where a bug produces confident wrong output
rather than a crash, which is the failure mode hardest to notice.

Tests are named for the behaviour they protect, not the method they call:
`PidReuse_ResolvesToTheGenerationAliveAtEventTime`, not `TestResolve2`.

Collector and UI code is harder to test automatically; describe your manual verification in
the PR, including whether you ran elevated.

## Claims about Windows behaviour

If you assert something about how Windows behaves — an event carries a field, an API has a
side effect, a format tolerates a modification — **verify it and say how**. The single-file
resource-patching finding in [PACKAGE-FORMAT.md](docs/PACKAGE-FORMAT.md) exists because it
was measured. A design built on a plausible-sounding assumption about ETW is how this class
of tool goes quietly wrong.

## Pull requests

- One concern per PR
- Say what you verified and how, especially for collector changes
- Note whether the change affects what a session records — that has privacy implications
- New evidence sources must set `EvidenceSource` and `AttributionConfidence` honestly

## Reporting bugs

Include the CaYaTrace version, the Windows build (`winver`), whether you ran elevated, and
the data-quality summary from the session header. A session that lost events looks exactly
like a program that did nothing, so that summary is usually the first useful clue.

Security issues go to [SECURITY.md](SECURITY.md), not the public tracker.
