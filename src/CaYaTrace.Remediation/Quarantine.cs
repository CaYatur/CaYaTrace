using System.Text;
using System.Text.Json;

namespace CaYaTrace.Remediation;

/// <summary>Where a removal has got to, reported as it goes.</summary>
/// <remarks>
/// <see cref="Kind"/> is null for the preparation steps — stopping a service, clearing a
/// recovery action — which are real work with real messages but are not items on the plan.
/// </remarks>
/// <param name="ValueName">Set for a registry value, so a key with several values reads right.</param>
/// <param name="Item">
/// The plan item this is about, or null for a preparation step.
/// </param>
/// <remarks>
/// <para>
/// The item is carried rather than described so a caller can match a report back to the
/// row it approved without reconstructing a key from the pieces. That mattered as soon as
/// the workbench started marking rows live: the runner reorders its work — services before
/// binaries, directories after their contents — so position says nothing, and a key built
/// from kind and path collapsed three values under one registry key onto one row.
/// </para>
/// <para>
/// Compared by reference at the far end, never by value, because two plan items can be
/// equal and still be different rows.
/// </para>
/// </remarks>
public sealed record RemediationProgress(
    int Index,
    int Total,
    RemovalKind? Kind,
    string Target,
    ItemOutcome? Outcome,
    string? Detail,
    string? ValueName = null,
    RemovalItem? Item = null)
{
    /// <summary>Zero until the first item, so a caller can show a bar that starts empty.</summary>
    public int Percent => Total <= 0 ? 0 : (int)Math.Round(Index * 100.0 / Total);

    /// <summary>True while the item is being worked on rather than finished.</summary>
    public bool Started => Outcome is null;

    /// <summary>True for the steps taken before the plan itself is carried out.</summary>
    public bool IsPreparation => Kind is null;
}

/// <summary>One thing sitting in quarantine, and where it came from.</summary>
public sealed record QuarantinedItem
{
    public required string QuarantinePath { get; init; }
    public required string OriginalPath { get; init; }
    public required DateTimeOffset MovedAt { get; init; }
    public long SizeBytes { get; init; }
    public bool IsDirectory { get; init; }

    /// <summary>True when the original location is free for a restore.</summary>
    public bool CanRestore { get; init; }
}

/// <summary>What the operator decided to do with what was quarantined.</summary>
public enum QuarantineDisposition
{
    /// <summary>Leave it where it is. The default, and the reversible one.</summary>
    Keep,

    /// <summary>Put it back where it came from.</summary>
    Restore,

    /// <summary>Delete it for good.</summary>
    Delete,
}

/// <summary>
/// The holding area a removal moves things into instead of deleting them.
/// </summary>
/// <remarks>
/// <para>
/// Quarantine is what makes a removal a decision the operator can change their mind
/// about. Nothing is deleted during a run; files are moved, registry values are exported
/// to a <c>.reg</c> first, and every step is written to a journal as it happens.
/// </para>
/// <para>
/// This class is the other end of that: reading back what is being held, putting it back,
/// or finally deleting it — which is the one operation here that cannot be undone, and so
/// is the one the operator has to ask for explicitly, after seeing the list.
/// </para>
/// </remarks>
public sealed class Quarantine
{
    private readonly string _root;

    public Quarantine(string root) => _root = root;

    public string Root => _root;

    private string JournalPath => Path.Combine(_root, "rollback-journal.jsonl");

    /// <summary>Everything currently held, newest first.</summary>
    public IReadOnlyList<QuarantinedItem> Contents()
    {
        var items = new List<QuarantinedItem>();
        if (!File.Exists(JournalPath)) return items;

        foreach (string line in ReadJournalLines())
        {
            JsonElement entry;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(line);
                entry = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue;
            }

            // Only the file-system entries are things sitting in quarantine. A service
            // registration and a registry value are exported to a .reg beside them and
            // are put back a different way.
            if (Text(entry, "kind") != "filesystem") continue;
            if (!entry.TryGetProperty("payload", out JsonElement payload)) continue;

            string? held = Text(payload, "quarantined");
            string? original = Text(payload, "original");
            if (held is not { Length: > 0 } || original is not { Length: > 0 }) continue;

            bool isDirectory = Directory.Exists(held);
            if (!isDirectory && !File.Exists(held)) continue;

            items.Add(new QuarantinedItem
            {
                QuarantinePath = held,
                OriginalPath = original,
                MovedAt = entry.TryGetProperty("at", out JsonElement at)
                          && at.TryGetDateTimeOffset(out DateTimeOffset moved)
                    ? moved
                    : DateTimeOffset.MinValue,
                IsDirectory = isDirectory,
                SizeBytes = SafeSize(held, isDirectory),
                CanRestore = !File.Exists(original) && !Directory.Exists(original),
            });
        }

        return items.OrderByDescending(static i => i.MovedAt).ToList();
    }

    /// <summary>
    /// Carries out the operator's decision.
    /// </summary>
    /// <remarks>
    /// <paramref name="disposition"/> of <see cref="QuarantineDisposition.Delete"/> is the
    /// only irreversible path in the whole tool. It is a separate, explicit call made
    /// after the operator has seen exactly what is on the list, and it refuses to touch
    /// anything outside the quarantine directory even if the journal says otherwise — a
    /// journal is a file, and a file that has been edited must not become a way to delete
    /// an arbitrary path.
    /// </remarks>
    public IReadOnlyList<(QuarantinedItem Item, bool Succeeded, string Message)> Apply(
        QuarantineDisposition disposition,
        IReadOnlyCollection<string>? only = null,
        Action<RemediationProgress>? progress = null)
    {
        var results = new List<(QuarantinedItem, bool, string)>();

        List<QuarantinedItem> targets = Contents()
            .Where(i => only is null || only.Contains(i.QuarantinePath, StringComparer.OrdinalIgnoreCase))
            .ToList();

        string root = Path.GetFullPath(_root).TrimEnd('\\') + "\\";
        int index = 0;

        foreach (QuarantinedItem item in targets)
        {
            index++;
            progress?.Invoke(new RemediationProgress(
                index, targets.Count, item.IsDirectory ? RemovalKind.Directory : RemovalKind.File,
                item.OriginalPath, null, null));

            (bool ok, string message) = disposition switch
            {
                QuarantineDisposition.Keep => (true, "left in quarantine"),
                QuarantineDisposition.Restore => Restore(item),
                QuarantineDisposition.Delete => Delete(item, root),
                _ => (false, "unknown disposition"),
            };

            results.Add((item, ok, message));
            progress?.Invoke(new RemediationProgress(
                index, targets.Count, item.IsDirectory ? RemovalKind.Directory : RemovalKind.File,
                item.OriginalPath, ok ? ItemOutcome.Removed : ItemOutcome.Failed, message));
        }

        return results;
    }

    private static (bool, string) Restore(QuarantinedItem item)
    {
        if (!item.CanRestore)
            return (false, $"something already exists at {item.OriginalPath}");

        try
        {
            string? parent = Path.GetDirectoryName(item.OriginalPath);
            if (parent is { Length: > 0 }) Directory.CreateDirectory(parent);

            if (item.IsDirectory) Directory.Move(item.QuarantinePath, item.OriginalPath);
            else File.Move(item.QuarantinePath, item.OriginalPath);

            return (true, $"restored to {item.OriginalPath}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Deletes a held item, having first confirmed it is actually held.
    /// </summary>
    /// <remarks>
    /// The containment check is not a formality. The path comes from a journal file on
    /// disk, and the only thing standing between a modified journal and a tool that
    /// deletes an arbitrary directory is this comparison.
    /// </remarks>
    private static (bool, string) Delete(QuarantinedItem item, string root)
    {
        string full = Path.GetFullPath(item.QuarantinePath);

        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            return (false, "refusing to delete something outside the quarantine directory");

        try
        {
            if (item.IsDirectory) Directory.Delete(full, recursive: true);
            else File.Delete(full);

            return (true, "deleted permanently");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false, ex.Message);
        }
    }

    private IEnumerable<string> ReadJournalLines()
    {
        string[] lines;
        try { lines = File.ReadAllLines(JournalPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (string line in lines)
            if (line.Length > 0) yield return line;
    }

    private static string? Text(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object
           && element.TryGetProperty(name, out JsonElement value)
           && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long SafeSize(string path, bool isDirectory)
    {
        try
        {
            if (!isDirectory) return new FileInfo(path).Length;

            return new DirectoryInfo(path)
                .EnumerateFiles("*", SearchOption.AllDirectories)
                .Sum(static f => f.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }


    /// <summary>A human-readable listing, for the CLI.</summary>
    public string Describe()
    {
        IReadOnlyList<QuarantinedItem> items = Contents();
        if (items.Count == 0) return "quarantine is empty";

        var sb = new StringBuilder();
        sb.AppendLine($"{items.Count} item(s) held in {_root}");

        foreach (QuarantinedItem item in items)
        {
            sb.Append("  ").Append(item.OriginalPath);
            if (item.SizeBytes > 0) sb.Append("  (").Append(item.SizeBytes / 1024).Append(" KB)");
            if (!item.CanRestore) sb.Append("  [something is there now]");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
