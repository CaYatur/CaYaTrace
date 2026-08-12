using System.Security.Cryptography;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;

namespace CaYaTrace.Analysis.Reputation;

/// <summary>Source of file reputation. Abstracted so the pipeline never needs a network.</summary>
public interface IReputationSource
{
    Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken = default);
}

public sealed class VirusTotalReputationSource : IReputationSource
{
    private readonly VirusTotalClient _client;

    public VirusTotalReputationSource(VirusTotalClient client) => _client = client;

    public Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken = default)
        => _client.LookupAsync(sha256, cancellationToken);
}

/// <summary>
/// Attaches file reputation to findings that warrant it.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately selective. A public API key allows four requests a minute, so checking
/// every artifact in a session would take hours and tell the operator little: the
/// interesting question is whether the <em>executables the subject dropped</em> are known bad,
/// not whether a log file is.
/// </para>
/// <para>
/// Files are hashed here rather than during collection. Hashing every write as it
/// happens would put file I/O on the collection path, which is the one place this
/// codebase does not allow it.
/// </para>
/// </remarks>
public sealed class ReputationEnricher
{
    private readonly IReputationSource _source;
    private readonly PathNormalizer _paths;

    /// <summary>Files above this size are not hashed; the read cost outweighs the value.</summary>
    private const long MaxHashBytes = 256L * 1024 * 1024;

    private static readonly string[] Interesting = { ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl" };

    public ReputationEnricher(IReputationSource source, PathNormalizer? paths = null)
    {
        _source = source;
        _paths = paths ?? PathNormalizer.CreateForCurrentMachine();
    }

    public Action<int, int, string>? OnProgress { get; init; }

    /// <summary>
    /// Looks up the executables among the given artifacts.
    /// </summary>
    /// <returns>Reputation keyed by the artifact's target path.</returns>
    public async Task<IReadOnlyDictionary<string, ReputationResult>> EnrichAsync(
        IEnumerable<ScoredArtifact> artifacts,
        int limit = 12,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, ReputationResult>(StringComparer.OrdinalIgnoreCase);

        List<ScoredArtifact> candidates = artifacts
            .Where(IsExecutableArtifact)
            .OrderByDescending(static a => a.Score)
            .ToList();

        // One lookup per distinct file, highest-scoring first, so a capped run spends
        // its quota on the artifacts most likely to matter.
        var byPath = new Dictionary<string, ScoredArtifact>(StringComparer.OrdinalIgnoreCase);
        foreach (ScoredArtifact artifact in candidates)
            byPath.TryAdd(artifact.Observation.Target, artifact);

        int index = 0;
        foreach ((string target, ScoredArtifact artifact) in byPath.Take(limit))
        {
            cancellationToken.ThrowIfCancellationRequested();
            OnProgress?.Invoke(++index, Math.Min(byPath.Count, limit), target);

            string concrete = _paths.Expand(target);
            string? sha = ComputeSha256(concrete);

            if (sha is null)
            {
                // The file is gone — deleted by the subject, or the artifact came from
                // another machine. That is worth saying rather than silently omitting.
                results[target] = ReputationResult.Unavailable(string.Empty,
                    "the file is no longer present on this machine, so it could not be hashed");
                continue;
            }

            results[target] = await _source.LookupAsync(sha, cancellationToken).ConfigureAwait(false);
            _ = artifact;
        }

        return results;
    }

    private bool IsExecutableArtifact(ScoredArtifact artifact)
    {
        if (artifact.Observation.Category != EventCategory.File) return false;
        if (!artifact.Observation.Action.IsPersistentChange()) return false;

        string extension = Path.GetExtension(artifact.Observation.Target);
        return Interesting.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    internal static string? ComputeSha256(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxHashBytes) return null;

            using FileStream stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
