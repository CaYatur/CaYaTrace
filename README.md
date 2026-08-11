<div align="center">

# CaYaTrace

**Windows application forensics — see exactly what a program does to your machine and to the network.**

[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-111826.svg)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-8.0-182438.svg)](#requirements)
[![Status](https://img.shields.io/badge/status-0.1.0%20preview-b91c1c.svg)](docs/ROADMAP.md)

[Türkçe README](README.tr.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Roadmap](docs/ROADMAP.md)

</div>

---

> [!WARNING]
> **Authorized use only.** Captured sessions can contain passwords, tokens, cookies, full
> URLs, request and response bodies, file contents, usernames, and other sensitive data. Use
> this only on systems you own or are explicitly authorized to test. Never commit a session
> to a public repository. See [SECURITY.md](SECURITY.md).

---

## What it does

Install monitors show you *what changed*. Network sniffers show you *what was sent*.
CaYaTrace joins the two into a single causal chain, so you can follow one thread from a
double-click all the way to an HTTPS request:

```
setup.exe
├─ msiexec.exe
│   ├─ FILE CREATE
│   │   └─ %PROGRAMFILES%\Example\example.exe
│   ├─ REGISTRY SET
│   │   └─ HKLM\...\Uninstall\Example::DisplayName
│   │       from: (not present)
│   │       to:   Example 2.1
│   └─ SERVICE CREATE
│       └─ ExampleService
│
└─ example.exe
    ├─ FILE CREATE
    │   └─ %APPDATA%\Example\config.json
    ├─ DNS
    │   └─ api.example.com
    └─ HTTP(S)
        └─ POST https://api.example.com/v3/register
            ├─ Request metadata
            ├─ Response metadata
            └─ 1.7 KB sent / 4.2 KB received
```

Then it turns that recording into a **portable removal package** you can carry to a machine
that has never run CaYaTrace and clean it there — with every item re-verified against that
machine before anything is touched.

## Why it is built the way it is

- **Correct attribution over more events.** PIDs get recycled; file and registry events carry
  pointers, not names. Getting these wrong produces a confident, *wrong* tree. See
  [the correlation layer](docs/ARCHITECTURE.md#3-the-correlation-layer-is-the-product).
- **Honest about what it missed.** ETW drops events silently under load, which makes a session
  look *cleaner* than reality. Every session reports its own data quality.
- **No kernel driver.** No install, no reboot, no test-signing mode, nothing left behind.
  [Why, and what it costs.](docs/ARCHITECTURE.md#1-the-constraint-that-shapes-everything-no-kernel-driver)
- **Removal that cannot brick the machine.** Non-overridable deny list, fingerprint
  verification, quarantine instead of delete, rollback journal, dry run by default.

## Status — 0.1.0 preview

This is an early release. What is real today versus designed is tracked honestly:

| Area | Status |
|---|---|
| Process / thread / module tracing, causal tree | ✅ working |
| File and registry tracing with name resolution | ✅ working |
| Registry before → after value transitions | ✅ working |
| Before/after system inventories + diff | ✅ working |
| Network flows with process attribution (kernel) | ✅ working |
| DNS queries and answers, attributed to the requesting process | ✅ working |
| TLS handshake metadata (Schannel) | ✅ working |
| Full URLs from WinINet / WinHTTP applications | ✅ working |
| Session storage, JSONL journal, data-quality reporting | ✅ working |
| Removal planner, `.ctpkg` packages, remediation runner | ✅ working |
| CLI (`trace`, `report`, `remediate`) | ✅ working |
| Workbench UI (WebView2 + CaYaDev theme) | 🚧 in progress |
| Packet capture via Pktmon | 📐 designed |
| Intercepting proxy for full request bodies (opt-in) | 📐 designed |
| Multi-VM comparison (`compare`) with measured path templating | ✅ working |
| VirusTotal and Ollama integration | 📐 designed |
| HTML / CSV export with category selection | 📐 designed |

## Quick start

Download `CaYaTrace.exe` from [Releases](https://github.com/CaYatur/CaYaTrace/releases). It is
portable — no installer, no service, nothing written outside its own folder.

```bash
CaYaTrace trace --target "C:\Downloads\setup.exe" --duration 120
```

Then render what it found:

```bash
CaYaTrace report --session .\sessions
```

Build a removal package from the recording:

```bash
CaYaTrace report --session .\sessions --export-package Example.ctpkg
```

Preview the removal on any machine (nothing is changed without `--apply`):

```bash
CaYaTrace remediate --package Example.ctpkg
```

Record the same program on two VMs, then compare — the parts that recur are its real
behaviour, and the paths that differ become *measured* patterns the package carries:

```bash
CaYaTrace compare .m-a .m-b --export-package Example.ctpkg
```

Run `CaYaTrace` with no arguments for the workbench UI, or `CaYaTrace help` for every option.

> **Kernel tracing needs an elevated prompt.** Without it CaYaTrace still records
> before/after system inventories, and tells you clearly what it skipped rather than
> pretending the program did nothing.

## Requirements

- Windows 10 (1809+) or Windows 11, x64 or ARM64
- Administrator rights for kernel tracing — everything else works unelevated
- [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) for the
  workbench UI (preinstalled on Windows 11; the CLI does not need it)

## Building from source

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/CaYatur/CaYaTrace.git
cd CaYaTrace
dotnet test
dotnet publish src/CaYaTrace.App -c Release -r win-x64 -o dist
```

Trimming is disabled deliberately —
[here is why](docs/ARCHITECTURE.md#9-packaging).

## Language

The interface follows the Windows display language: Turkish on a Turkish system, English
everywhere else. Set `CAYATRACE_LANGUAGE=en` or `=tr` to override.

Operation names in the tree (`FILE CREATE`, `REGISTRY SET`) stay in English in every
language, so reports remain diffable and searchable across locales.

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | How the engine works, and the limits it has |
| [Package format](docs/PACKAGE-FORMAT.md) | The `.ctpkg` removal package |
| [Roadmap](docs/ROADMAP.md) | What is planned, in what order |
| [Security](SECURITY.md) | Handling captured evidence; reporting vulnerabilities |
| [Contributing](CONTRIBUTING.md) | |

## Related

[CaYa Network Forensic Observer](https://github.com/CaYatur/CaYa-Network-Forensic-Observer) —
the network-only predecessor. CaYaTrace supersedes it by adding system-change tracing, causal
correlation, and remediation.

## License

MIT © 2026 [CaYatur](https://github.com/CaYatur) · [CaYaDev](https://cayadev.com)
