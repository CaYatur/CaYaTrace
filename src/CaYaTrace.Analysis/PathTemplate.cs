using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace CaYaTrace.Analysis;

public enum SegmentKind
{
    /// <summary>The segment is the same everywhere and must match exactly.</summary>
    Literal = 0,

    /// <summary>The segment differs between installations and matches anything.</summary>
    Variable = 1,
}

/// <summary>How the variability of a template was established.</summary>
public enum TemplateEvidence
{
    /// <summary>
    /// The path was seen once. Variable segments are a heuristic guess and could be
    /// wrong in either direction.
    /// </summary>
    Inferred = 0,

    /// <summary>
    /// The same artifact was seen on two or more machines and the segments that
    /// actually differed were taken as the variables. This is a measurement, not a
    /// guess, and it is why multi-VM capture produces better removal packages.
    /// </summary>
    Observed = 1,
}

public sealed record PathSegment(string Text, SegmentKind Kind)
{
    public override string ToString() => Kind == SegmentKind.Variable ? "{*}" : Text;
}

/// <summary>
/// A path with its machine-specific parts marked, so it can be matched on a machine
/// that spells them differently.
/// </summary>
/// <remarks>
/// <para>
/// The problem this solves is concrete. A dropper writes
/// <c>%APPDATA%\a8f3c1d0\svc.exe</c> on one VM and <c>%APPDATA%\d92b4711\svc.exe</c> on
/// another. Those are the same artifact, but a removal package built from either one
/// matches nothing on a third machine. Tokenizing the known-folder prefix
/// (<see cref="Core.Naming.PathNormalizer"/>) handles the part that varies by machine
/// layout; this handles the part that varies by <em>run</em>.
/// </para>
/// <para>
/// Templates are never applied silently. A variable segment widens what a removal plan
/// will match, so <see cref="Evidence"/> is carried through to the plan and an inferred
/// template requires confirmation before anything is removed.
/// </para>
/// </remarks>
public sealed class PathTemplate
{
    public IReadOnlyList<PathSegment> Segments { get; }

    public TemplateEvidence Evidence { get; }

    /// <summary>Concrete values seen in the variable slots, for the analyst to inspect.</summary>
    public IReadOnlyList<string> Examples { get; }

    public PathTemplate(IReadOnlyList<PathSegment> segments, TemplateEvidence evidence, IReadOnlyList<string>? examples = null)
    {
        Segments = segments;
        Evidence = evidence;
        Examples = examples ?? Array.Empty<string>();
    }

    public bool HasVariables => Segments.Any(static s => s.Kind == SegmentKind.Variable);

    /// <summary>The template in display form, e.g. <c>%APPDATA%\{*}\svc.exe</c>.</summary>
    public string Pattern => string.Join('\\', Segments.Select(static s => s.ToString()));

    /// <summary>
    /// Stable identity for grouping. Two paths that differ only in their variable
    /// slots produce the same signature.
    /// </summary>
    public string Signature => Pattern.ToUpperInvariant();

    public override string ToString() => Pattern;

    /// <summary>
    /// True when a concrete tokenized path fits this template.
    /// </summary>
    /// <remarks>
    /// Segment count must match exactly. A template deliberately does not match across
    /// directory depths: <c>%APPDATA%\{*}\svc.exe</c> matching
    /// <c>%APPDATA%\a\b\svc.exe</c> would let one recorded artifact authorize removing a
    /// file in an unrelated location.
    /// </remarks>
    public bool Matches(string? tokenizedPath)
    {
        if (string.IsNullOrEmpty(tokenizedPath)) return false;

        string[] parts = Split(tokenizedPath);
        if (parts.Length != Segments.Count) return false;

        for (int i = 0; i < parts.Length; i++)
        {
            if (Segments[i].Kind == SegmentKind.Variable) continue;
            if (!string.Equals(parts[i], Segments[i].Text, StringComparison.OrdinalIgnoreCase)) return false;
        }

        return true;
    }

    internal static string[] Split(string path)
        => path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>
/// Derives <see cref="PathTemplate"/> values, preferring measurement over guesswork.
/// </summary>
public static class PathTemplater
{
    /// <summary>
    /// Builds a template from the same artifact seen on several machines.
    /// </summary>
    /// <remarks>
    /// This is the accurate path and the reason multi-VM capture is worth doing. No
    /// heuristic is involved: the segments that differ across observations <em>are</em> the
    /// variables, and the ones that agree are literals. Two observations are enough,
    /// and more only sharpen it.
    /// </remarks>
    public static PathTemplate? FromObservations(IEnumerable<string> tokenizedPaths)
    {
        List<string[]> candidates = tokenizedPaths
            .Where(static p => !string.IsNullOrWhiteSpace(p))
            .Select(PathTemplate.Split)
            .ToList();

        if (candidates.Count == 0) return null;
        if (candidates.Count == 1) return Infer(string.Join('\\', candidates[0]));

        int length = candidates[0].Length;
        // Different depths are different artifacts, not one artifact with a variable
        // depth. Aligning them positionally would produce nonsense.
        if (candidates.Any(c => c.Length != length)) return null;

        var segments = new List<PathSegment>(length);
        var examples = new List<string>();

        for (int i = 0; i < length; i++)
        {
            string first = candidates[0][i];
            bool allAgree = candidates.All(c => string.Equals(c[i], first, StringComparison.OrdinalIgnoreCase));

            if (allAgree)
            {
                segments.Add(new PathSegment(first, SegmentKind.Literal));
            }
            else
            {
                segments.Add(new PathSegment(first, SegmentKind.Variable));
                examples.AddRange(candidates.Select(c => c[i]).Distinct(StringComparer.OrdinalIgnoreCase));
            }
        }

        return new PathTemplate(segments, TemplateEvidence.Observed, examples);
    }

    /// <summary>
    /// Guesses a template from a single observation.
    /// </summary>
    /// <remarks>
    /// The fallback when only one machine was recorded. It marks segments that look
    /// machine- or run-specific — GUIDs, long hex strings, temp names, high-entropy
    /// mixed-class tokens — and is wrong in both directions sometimes: a legitimately
    /// named folder can look random, and a short random name can look like a word. That
    /// is why the result is tagged <see cref="TemplateEvidence.Inferred"/> and never
    /// silently widens a removal.
    /// </remarks>
    public static PathTemplate Infer(string tokenizedPath)
    {
        string[] parts = PathTemplate.Split(tokenizedPath);
        var segments = new List<PathSegment>(parts.Length);
        var examples = new List<string>();

        for (int i = 0; i < parts.Length; i++)
        {
            // The final segment is the file name. Treated as a literal unless it is
            // strongly random: a template whose leaf matches anything would authorize
            // removing every file in a directory.
            bool isLeaf = i == parts.Length - 1;
            bool variable = isLeaf ? LooksStronglyRandom(parts[i]) : LooksVariable(parts[i]);

            segments.Add(new PathSegment(parts[i], variable ? SegmentKind.Variable : SegmentKind.Literal));
            if (variable) examples.Add(parts[i]);
        }

        return new PathTemplate(segments, TemplateEvidence.Inferred, examples);
    }

    private static readonly Regex GuidLike = new(
        @"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex TempName = new(
        @"^(tmp|temp|~|\$)[0-9a-zA-Z]{4,}(\.tmp)?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// Directory-level variability test.
    /// </summary>
    internal static bool LooksVariable(string segment)
    {
        if (segment.Length == 0) return false;
        if (GuidLike.IsMatch(segment)) return true;
        if (TempName.IsMatch(segment)) return true;

        string bare = segment.Trim('{', '}');

        // A long pure-hex run is an identifier, not a name. Eight is the shortest
        // length at which this is more likely deliberate than coincidental — "deadbeef"
        // exists, but a folder called "abcdef" does not warrant widening a removal.
        if (bare.Length >= 8 && bare.All(static c => Uri.IsHexDigit(c))) return true;

        // Pure digits of some length: build numbers, timestamps, PIDs.
        if (bare.Length >= 6 && bare.All(char.IsDigit)) return true;

        return LooksStronglyRandom(bare);
    }

    /// <summary>
    /// Stricter test, used for file names where a false positive is more costly.
    /// </summary>
    internal static bool LooksStronglyRandom(string segment)
    {
        // Compare the stem only; an extension is meaningful and should not dilute the
        // entropy estimate.
        string stem = Path.GetFileNameWithoutExtension(segment);
        if (stem.Length < 10) return false;
        if (GuidLike.IsMatch(stem)) return true;

        bool hasUpper = stem.Any(char.IsUpper);
        bool hasLower = stem.Any(char.IsLower);
        bool hasDigit = stem.Any(char.IsDigit);

        // Real names are usually words, or words with separators. Requiring mixed case
        // *and* digits *and* no separators keeps ordinary names such as
        // "SetupHelper64" or "app-config-v2" out.
        if (stem.Contains('-') || stem.Contains('_') || stem.Contains('.')) return false;
        if (!(hasUpper && hasLower && hasDigit)) return false;

        return ShannonEntropy(stem) >= 3.2;
    }

    /// <summary>
    /// Shannon entropy in bits per character.
    /// </summary>
    /// <remarks>
    /// Around 3.2 separates generated identifiers from English-like names in practice:
    /// natural words cluster near 2.5–3.0 because letters repeat, while base32 or
    /// base64 output sits above 4. It is a weak signal on its own, which is why it is
    /// only consulted after the character-class checks have already passed.
    /// </remarks>
    internal static double ShannonEntropy(string value)
    {
        if (value.Length == 0) return 0;

        var counts = new Dictionary<char, int>(value.Length);
        foreach (char c in value)
        {
            char k = char.ToLowerInvariant(c);
            counts[k] = counts.GetValueOrDefault(k) + 1;
        }

        double entropy = 0;
        foreach (int count in counts.Values)
        {
            double p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    /// <summary>
    /// Expands a template against a machine, returning every existing path that fits.
    /// </summary>
    /// <remarks>
    /// Enumerates only the directories a variable slot actually sits in, rather than
    /// walking the tree, so a template with a variable near the root cannot turn into a
    /// full-disk scan. Returns concrete paths for the caller to verify individually —
    /// matching a template is never on its own sufficient grounds to remove something.
    /// </remarks>
    public static IReadOnlyList<string> Expand(PathTemplate template, Core.Naming.PathNormalizer paths)
    {
        var frontier = new List<string> { string.Empty };

        for (int i = 0; i < template.Segments.Count; i++)
        {
            PathSegment segment = template.Segments[i];
            bool isLast = i == template.Segments.Count - 1;
            var next = new List<string>();

            foreach (string prefix in frontier)
            {
                if (segment.Kind == SegmentKind.Literal)
                {
                    next.Add(prefix.Length == 0 ? segment.Text : $"{prefix}\\{segment.Text}");
                    continue;
                }

                string parent = paths.Expand(prefix);
                if (parent.Length == 0 || !Directory.Exists(parent)) continue;

                try
                {
                    IEnumerable<string> matches = isLast
                        ? Directory.EnumerateFileSystemEntries(parent)
                        : Directory.EnumerateDirectories(parent);

                    foreach (string match in matches)
                        next.Add($"{prefix}\\{Path.GetFileName(match)}");
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    // An inaccessible directory contributes nothing; it is not an error.
                }
            }

            frontier = next;

            // A variable slot in a large directory can multiply the frontier without
            // bound. Capping keeps expansion predictable, and a template this loose is
            // not one a removal plan should act on anyway.
            if (frontier.Count > 4096) break;
        }

        return frontier
            .Select(paths.Expand)
            .Where(static p => p.Length > 0 && (File.Exists(p) || Directory.Exists(p)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Human-readable summary for the plan review screen.</summary>
    public static string Describe(PathTemplate template)
    {
        if (!template.HasVariables) return template.Pattern;

        var sb = new StringBuilder(template.Pattern);
        sb.Append(CultureInfo.InvariantCulture, $"  ({template.Evidence.ToString().ToLowerInvariant()}");
        if (template.Examples.Count > 0)
            sb.Append(CultureInfo.InvariantCulture, $"; seen as {string.Join(", ", template.Examples.Take(3))}");
        sb.Append(')');
        return sb.ToString();
    }
}
