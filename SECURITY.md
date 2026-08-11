# Security

## Authorized use only

CaYaTrace is a dual-use tool. The same capability that shows you what an installer changed
also shows you what any program on the machine is doing. Use it only on systems you own or
are explicitly authorized to test or investigate.

## What a captured session contains

Treat a session directory as **sensitive evidence**, at the same level as a memory dump.
Depending on which layers were enabled, it can hold:

- Full file paths, including user profile and document paths
- Registry values, which routinely contain licence keys, tokens, and credentials
- Command lines, which frequently contain passwords passed as arguments
- Usernames, SIDs, machine names, and hostnames
- DNS queries and TLS server names, revealing everything the machine talked to
- With the intercepting proxy enabled: **full HTTP request and response bodies**, including
  authentication headers, session cookies, and uploaded files

The repository's `.gitignore` excludes `sessions/`, `logs/`, `*.ctpkg`, `*.etl`, and
`*.pcapng` so captured data cannot be committed by accident. **Do not defeat this.** If you
need to attach a session to a bug report, redact it first or share it privately.

## The intercepting proxy and the temporary CA

Full HTTPS visibility requires a local intercepting proxy and a temporary certificate
authority in the Windows trust store. This is the single sharpest change CaYaTrace can make
to a system, and it is treated accordingly:

- **Off by default.** It is never enabled implicitly.
- **Per-session opt-in**, behind an explicit confirmation that names what will be installed.
- **A fresh CA per session.** No key material is reused or shipped with the tool.
- **Removed on session end**, and again on the next launch if the previous run was
  interrupted. The certificate store is snapshotted before and after so the removal can be
  *proven* rather than assumed.
- The CA thumbprint and its removal status are recorded in the session metadata.

While it is active, all traffic through that proxy is decryptable by anything running as
your user. Do not enable it on a machine you also use for anything else, and prefer a
disposable VM.

CaYaTrace does **not** implement bypasses for certificate pinning, ECH, custom trust stores,
or proxy-avoidance behaviour. Traffic from applications using those will remain opaque. This
is a deliberate limit: defeating an application's security controls is an evasion feature,
not an analysis one.

## Running against malware

If you are analysing something hostile:

- **Use a disposable VM with no network path to anything you care about.** CaYaTrace observes;
  it does not contain or sandbox.
- Kernel tracing requires an elevated process, so CaYaTrace runs with the same privileges the
  sample may try to abuse.
- CaYaTrace does not hide itself. A sample can see the ETW session and the process. VM
  detection is *reported*, not defeated.
- Snapshot-based evidence survives a sample that kills the tool; the append-only
  `raw-events.jsonl` is written continuously for the same reason.

## Remediation safety

Applying a removal package is destructive by nature. The following are structural properties,
not options:

- A **non-overridable deny list** covering Windows-owned paths, boot-critical registry
  subtrees, core services, and shared containers. There is no force flag.
- **Fingerprint verification** before every action. An item whose live hash, value data, or
  command line contradicts the recording is skipped and reported.
- **Quarantine, never delete.** Files are moved; registry keys are exported to `.reg` first.
- A **rollback journal** written as the run proceeds, so an interrupted run stays reversible.
- **Dry run by default.**

Take a system restore point before applying a package to a machine you cannot reimage.

### Package trust

`.ctpkg` packages carry a SHA-256 of their plan, which detects damage and casual tampering.
They are **not signed** in 0.1, so that hash is an integrity check, not an authenticity one —
anyone who edits a plan can recompute it.

**Treat a package with exactly the trust you have in whoever gave it to you.** Review the
dry-run output before applying anything you did not create yourself.

## Reporting a vulnerability

Report security issues privately — please do not open a public issue.

- GitHub: [private security advisory](https://github.com/CaYatur/CaYaTrace/security/advisories/new)
- Email: cayatur@gmail.com

Please include the version, the OS build, what you observed, and steps to reproduce. Expect
an initial response within a week.

Especially interested in: paths that defeat the remediation deny list, ways a crafted
`.ctpkg` could cause damage the dry run did not disclose, and failures that leave the
temporary CA installed.
