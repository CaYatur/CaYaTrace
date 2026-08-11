# The `.ctpkg` removal package

A removal package is the bridge between "I watched this install in a VM" and "clean it off
that machine over there". It is self-contained: the target machine needs `CaYaTrace.exe` and
the `.ctpkg`, nothing else — no session database, no network access, no prior run.

## Why a sidecar and not an embedded payload

The obvious design is a single self-extracting executable: copy `CaYaTrace.exe`, patch the
plan into it, hand over one file. **That does not work with .NET single-file publishing, and
this was measured rather than assumed.**

Patching a payload into a published single-file host via
`BeginUpdateResource` / `UpdateResource` / `EndUpdateResource`:

| | |
|---|---|
| Original published host | 67,486,287 bytes — runs |
| After a 4 KB resource write | **9,645,568 bytes** — fails to launch |
| Error | `Failure processing application bundle; possible file corruption.` |

`EndUpdateResource` rewrites the PE image and discards the appended bundle payload that the
single-file host depends on. The API reports success; the binary is destroyed.

There is a second, independent reason to prefer a sidecar even where embedding would work: an
exported remediator gets carried onto a machine that may be infected and is likely running
aggressive endpoint protection. A self-copying, self-modifying executable is precisely the
behaviour that gets quarantined. **The remediator should be boring.**

## Layout

A `.ctpkg` is a ZIP archive:

```
Example.ctpkg
├── manifest.json      package identity, origins, plan hash
├── plan.json          the removal items
└── evidence.jsonl     optional — the observations each item derives from
```

Plain ZIP so it can be inspected with any tool. A package you were handed should be opened
and read before it is applied.

### `manifest.json`

```jsonc
{
  "PackageId": "ctpkg_20260811_182942_b210",
  "SubjectName": "setup.exe",
  "SubjectPath": "C:\\Downloads\\setup.exe",
  "SubjectSha256": "9f2c…",
  "CreatedAt": "2026-08-11T15:30:39+00:00",
  "ToolVersion": "0.1.0.0",
  "FormatVersion": 1,
  "ItemCount": 47,
  "PlanHash": "3a91…",          // SHA-256 over plan.json
  "Origins": [ /* MachineProfile per machine the evidence came from */ ]
}
```

`Origins` carries each source machine's volume map and known-folder layout. That is what lets
a path recorded as `%APPDATA%\Example` on one machine resolve correctly on another where the
user account, drive letters, or Windows install location differ.

`PlanHash` is an **integrity** check, not an authenticity one. Packages are unsigned in 0.1;
anyone who edits the plan can recompute the hash. What actually protects the operator is that
every item is shown and re-verified before it is touched. See [SECURITY.md](../SECURITY.md).

### `plan.json`

```jsonc
[
  {
    "Kind": "File",
    "Target": "%PROGRAMFILES%\\Example\\example.exe",   // tokenized, not absolute
    "Fingerprint": {
      "Sha256": "c41d…",
      "Size": 284160,
      "Signer": "Example Ltd",
      "Signature": "SignedValid"
    },
    "Rationale": "created by setup.exe (4812)",
    "Evidence": [1043, 1044],
    "ObservedOn": ["a1b2c3d4", "e5f6a7b8"]              // machine ids
  },
  {
    "Kind": "RegistryValue",
    "Target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "ValueName": "ExampleUpdater",
    "Fingerprint": { "ValueData": "\"C:\\Program Files\\Example\\upd.exe\" /silent" },
    "Rationale": "set by example.exe (5120)"
  }
]
```

**Targets are tokenized.** `%APPDATA%`, `%PROGRAMFILES%`, `%WINDIR%` are expanded against the
machine the package is applied to, not the one that recorded it.

**Fingerprints are the safety mechanism.** The same path on a different machine may hold an
entirely unrelated file. Before touching anything the runner re-reads the live artifact and
compares:

| Result | Meaning | Action |
|---|---|---|
| `Exact` | Hash, value data, or command line matches | proceed |
| `Partial` | Only size matches | ask the operator |
| `Unknown` | Nothing comparable was recorded | ask the operator |
| `Conflict` | Something is there, and it is demonstrably not what was recorded | **skip and report** |

`ObservedOn` lists the machines an artifact appeared on. During multi-VM analysis, an artifact
seen on every VM is part of the program's fixed behaviour; one seen on a single VM is likely
machine-specific randomness. `--min-origins` filters on this.

## Ordering

Items carry an implicit order so removal cannot deadlock itself:

```
Service → ScheduledTask → AutorunEntry → FirewallRule
        → RegistryValue → File → RegistryKey → Directory → Certificate
```

A service is stopped before its binary is moved. Files go before the directory containing
them. Within an order tier, longer paths run first so children precede parents.

## What the runner leaves behind

Applying a package with `--apply` produces a quarantine directory:

```
quarantine/
├── rollback-journal.jsonl     one line per action, written as it happens
├── files/
│   └── C/Program Files/Example/example.exe
├── registry/
│   ├── HKLM_SOFTWARE_Example.reg
│   └── HKLM_..._Run__ExampleUpdater.reg
└── tasks/
    └── Example/Updater.xml
```

Nothing is deleted. Verify the machine behaves as expected, then remove the quarantine folder
yourself — that final deletion is deliberately the operator's decision, not the tool's.

## Compatibility

`FormatVersion` gates readability. A package written by a newer CaYaTrace than the one
reading it is **refused with a clear message** rather than partially understood — a removal
plan half-parsed is a removal plan that removes the wrong things.
