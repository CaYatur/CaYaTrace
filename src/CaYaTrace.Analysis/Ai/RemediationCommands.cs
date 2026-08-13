using System.Text;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Analysis.Ai;

/// <summary>A command the operator can run, with what it does and what it costs.</summary>
public sealed record GeneratedCommand
{
    public required string Subject { get; init; }

    /// <summary>The commands, in the order they must be run.</summary>
    public IReadOnlyList<string> Lines { get; init; } = Array.Empty<string>();

    /// <summary>Why this is safe to run, or why it is being refused.</summary>
    public required string Rationale { get; init; }

    /// <summary>True when nothing should be run and the rationale says why.</summary>
    public bool Refused { get; init; }

    public bool NeedsElevation { get; init; } = true;
}

/// <summary>
/// Turns "how do I get rid of this one" into the command for that one thing.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of what happened without it. Asked how to remove the suspicious
/// services it had just listed, a local model produced instructions to delete
/// <c>NlaSvc</c> — Network Location Awareness, a Windows service the network stack depends
/// on — and <c>Revoflt</c>, a filter driver belonging to the operator's own uninstaller,
/// and then to reset the network adapter. It did that because it was handed a list of four
/// services and asked to write removal steps, and a language model asked to write removal
/// steps writes removal steps for everything it was given.
/// </para>
/// <para>
/// So the model is out of this path entirely. Commands are built from the session's own
/// record of the thing: the service name it was registered under, the image path the
/// registry actually holds, the task path the scheduler actually has. Nothing here is
/// generated text.
/// </para>
/// <para>
/// And the gate is the analyzer's own verdict rather than a list of names to avoid. If the
/// scoring did not find a reason to be suspicious of something, the tool has no business
/// handing over a command to delete it — that is the same judgement the removal planner
/// makes, applied at the point where the operator is about to act on a chat message.
/// </para>
/// </remarks>
public static class RemediationCommands
{
    /// <summary>
    /// Builds the removal for one persistence record.
    /// </summary>
    /// <remarks>
    /// Order matters and is not cosmetic. A service that is still running holds its image
    /// open, so deleting the file first fails and leaves the service registered — which is
    /// the state where the operator believes they have removed something and have not.
    /// </remarks>
    public static GeneratedCommand ForPersistence(PersistenceRecord record)
    {
        if (record.Risk < RiskLevel.Medium)
        {
            return new GeneratedCommand
            {
                Subject = record.Identity,
                Refused = true,
                Rationale =
                    $"CaYaTrace did not find a reason to be suspicious of {record.Identity} "
                    + $"(scored {record.Risk}). It is listed because it arranges to run again, which "
                    + "most of what a machine relies on also does. Removing it on that basis alone is "
                    + "how a working system gets broken — say explicitly that you want it gone if you "
                    + "have a reason the recording does not show.",
            };
        }

        var lines = new List<string>();

        switch (record.Kind)
        {
            case PersistenceKind.Service:
                lines.Add($"sc.exe stop \"{record.Identity}\"");
                lines.Add($"sc.exe delete \"{record.Identity}\"");
                break;

            case PersistenceKind.ScheduledTask:
                lines.Add($"schtasks.exe /Delete /TN \"{record.Identity}\" /F");
                break;

            default:
                // Everything else is a registry value that names something to run.
                (string key, string? value) = SplitRegistry(record.Location, record.Identity);
                lines.Add(value is null
                    ? $"Remove-Item -LiteralPath '{key}' -Recurse -Force"
                    : $"Remove-ItemProperty -LiteralPath '{key}' -Name '{value}' -Force");
                break;
        }

        if (ExecutablePath(record.Command) is { Length: > 0 } image)
            lines.Add($"Remove-Item -LiteralPath '{image}' -Force");

        return new GeneratedCommand
        {
            Subject = record.Identity,
            Lines = lines,
            Rationale = Because(record),
        };
    }

    /// <summary>Ends one process, by the identity the session recorded for it.</summary>
    /// <remarks>
    /// Refuses to write a command against anything Windows signed. A process the operator
    /// wants stopped is one thing; a one-liner that stops a signed system process is a way
    /// to lose a machine, and the answer they wanted is almost always about its parent.
    /// </remarks>
    public static GeneratedCommand ForProcess(ProcessNode process)
    {
        if (process.IsMicrosoftSigned())
        {
            return new GeneratedCommand
            {
                Subject = process.ImageName,
                Refused = true,
                Rationale =
                    $"{process.ImageName} carries a valid Microsoft signature, so this will not write a "
                    + "command to end it. If it is doing something it should not, what matters is what "
                    + "asked it to — look at what started it, not at the process itself.",
                NeedsElevation = false,
            };
        }

        return new GeneratedCommand
        {
            Subject = $"{process.ImageName} (PID {process.Key.Pid})",
            Lines = new[]
            {
                $"Stop-Process -Id {process.Key.Pid} -Force",
            },
            Rationale =
                $"Ends the process the session recorded as {process.ImageName}, PID {process.Key.Pid}. "
                + "If it is being restarted by a service or a scheduled task, remove that first or it "
                + "will simply come back.",
        };
    }

    /// <summary>Deletes one file the session saw written.</summary>
    public static GeneratedCommand ForFile(string path, bool suspicious)
    {
        if (!suspicious)
        {
            return new GeneratedCommand
            {
                Subject = path,
                Refused = true,
                Rationale =
                    $"Nothing in the session marked {path} as suspicious, and it is not being turned "
                    + "into a delete command on the strength of having been written. Ask about it "
                    + "specifically if you have a reason to.",
            };
        }

        return new GeneratedCommand
        {
            Subject = path,
            Lines = new[]
            {
                $"Remove-Item -LiteralPath '{path}' -Force",
            },
            Rationale =
                "Deletes the file outright. If you may need it later — and for anything you intend to "
                + "submit or analyse, you will — use the Remediate view instead, which quarantines a "
                + "copy before removing it.",
        };
    }

    /// <summary>
    /// The tool's own reasons, verbatim.
    /// </summary>
    /// <remarks>
    /// The reasons come from the scoring rules, so an operator can see the case against
    /// something before running a command that deletes it, and disagree with it.
    /// </remarks>
    private static string Because(PersistenceRecord record)
    {
        var text = new StringBuilder();
        text.Append(record.Kind).Append(' ').Append(record.Identity)
            .Append(" was scored ").Append(record.Risk).Append('.');

        if (record.Reasons.Count > 0)
            text.Append(' ').Append(string.Join("; ", record.Reasons.Take(4))).Append('.');

        if (record.RestartsItself)
        {
            text.Append(" It is configured to restart itself on failure, so stopping it without "
                      + "deleting it will not keep it stopped.");
        }

        return text.ToString();
    }

    /// <summary>
    /// The executable inside a command line.
    /// </summary>
    /// <remarks>
    /// A service's command is a command line, not a path: it can be quoted, and it can
    /// carry arguments. Handing the whole string to <c>Remove-Item</c> would either fail or,
    /// worse, delete something whose name happened to parse.
    /// </remarks>
    private static string ExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;

        string text = command.Trim();

        if (text.StartsWith('"'))
        {
            int closing = text.IndexOf('"', 1);
            return closing > 1 ? text[1..closing] : string.Empty;
        }

        // Unquoted: take up to the first switch, which is where arguments start in
        // practice for anything registered this way.
        int flag = text.IndexOf(" -", StringComparison.Ordinal);
        int slash = text.IndexOf(" /", StringComparison.Ordinal);
        int end = flag < 0 ? slash : slash < 0 ? flag : Math.Min(flag, slash);

        string candidate = (end > 0 ? text[..end] : text).Trim();

        // Only something that looks like a real file on disk, so a driver registered as
        // "system32\DRIVERS\x.sys" does not become a delete against a relative path.
        return candidate.Contains(":\\", StringComparison.Ordinal) && candidate.Contains('.')
            ? candidate
            : string.Empty;
    }

    private static (string Key, string? Value) SplitRegistry(string location, string identity)
    {
        // Persistence locations are recorded as a key, with the value name held separately
        // as the identity — except for the kinds whose identity *is* the key.
        string key = location.Replace("HKLM\\", "HKLM:\\", StringComparison.OrdinalIgnoreCase)
                             .Replace("HKCU\\", "HKCU:\\", StringComparison.OrdinalIgnoreCase);

        if (identity.Contains("::", StringComparison.Ordinal))
        {
            string[] parts = identity.Split("::", 2);
            return (parts[0].Replace("HKLM\\", "HKLM:\\", StringComparison.OrdinalIgnoreCase)
                            .Replace("HKCU\\", "HKCU:\\", StringComparison.OrdinalIgnoreCase),
                    parts[1]);
        }

        return key.EndsWith(identity, StringComparison.OrdinalIgnoreCase) ? (key, null) : (key, identity);
    }
}
