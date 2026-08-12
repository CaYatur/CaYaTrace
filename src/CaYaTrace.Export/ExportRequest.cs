using CaYaTrace.Core.Model;

namespace CaYaTrace.Export;

public enum ExportFormat
{
    /// <summary>One self-contained page: the workbench view with the data baked in.</summary>
    Html = 0,

    Json = 1,

    /// <summary>One row per observation, for a spreadsheet.</summary>
    Csv = 2,

    /// <summary>The causal tree as plain text.</summary>
    Tree = 3,

    /// <summary>A portable removal package.</summary>
    Package = 4,
}

/// <summary>
/// How much of a session an export carries.
/// </summary>
/// <remarks>
/// Three levels rather than a size slider, because the honest choices are qualitative.
/// <see cref="Minimal"/> is for a reader who wants to know what happened and will not
/// open a tree. <see cref="Standard"/> is the analyst's working copy. <see cref="Full"/>
/// is the archive — everything recorded, including reads and activity that was never
/// attributed to the subject, which is what a second opinion needs and what makes the
/// file large.
/// </remarks>
public enum ExportScope
{
    Minimal = 0,
    Standard = 1,
    Full = 2,
}

public sealed record ExportRequest
{
    public ExportFormat Format { get; init; } = ExportFormat.Html;

    public ExportScope Scope { get; init; } = ExportScope.Standard;

    /// <summary>Categories to include. Null or empty means every category.</summary>
    public IReadOnlyList<EventCategory>? Categories { get; init; }

    /// <summary>Language tag for rendered text in the HTML report.</summary>
    public string Language { get; init; } = "en";

    public bool IncludeReads => Scope == ExportScope.Full;

    public bool IncludeOutOfScope => Scope == ExportScope.Full;

    /// <summary>
    /// How many findings to carry.
    /// </summary>
    /// <remarks>
    /// A minimal report is a summary and stops at the part a person will actually read.
    /// A full one is an archive and should not silently truncate.
    /// </remarks>
    public int FindingLimit => Scope switch
    {
        ExportScope.Minimal => 40,
        ExportScope.Standard => 150,
        _ => 2000,
    };

    /// <summary>Rows per network table. Bounded so one chatty session cannot produce an unopenable file.</summary>
    public int NetworkRowLimit => Scope switch
    {
        ExportScope.Minimal => 200,
        ExportScope.Standard => 3_000,
        _ => 50_000,
    };

    public int MaxArtifactsPerGroup => Scope switch
    {
        ExportScope.Minimal => 50,
        ExportScope.Standard => 400,
        _ => 20_000,
    };

    /// <summary>The tree is the part a minimal report drops entirely.</summary>
    public bool IncludeTree => Scope != ExportScope.Minimal;

    public string DefaultExtension => Format switch
    {
        ExportFormat.Html => ".html",
        ExportFormat.Json => ".json",
        ExportFormat.Csv => ".csv",
        ExportFormat.Tree => ".txt",
        _ => ".ctpkg",
    };

    public bool Allows(EventCategory category)
        => Categories is null || Categories.Count == 0 || Categories.Contains(category);
}
