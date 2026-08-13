using System.Text.RegularExpressions;

namespace CaYaTrace.Analysis.Ai;

/// <summary>
/// The specific things a question names, as opposed to the topic it is about.
/// </summary>
/// <remarks>
/// <para>
/// Asking "is anything connecting to example.com" is a question about one host. Answering
/// it with every host in the session — including Windows' own connectivity checks — is
/// not a worse answer to that question, it is an answer to a different one, and the
/// operator then has to do the filtering the tool was asked to do. Measured, from a real
/// session: five hosts returned, one asked about.
/// </para>
/// <para>
/// Names are recognised by matching the question against what the session actually
/// contains, not by guessing at a shape. A service called <c>61df826a3fa71fa6</c> matches no
/// pattern anybody could write down; it matches because the session has a service by that
/// name. Literals — an address, a port, a registry path — are matched by pattern as well,
/// because the operator can reasonably ask about something the session never recorded, and
/// "nothing in this session touched that" is a real answer.
/// </para>
/// </remarks>
public sealed record QuestionEntities
{
    public IReadOnlyList<string> Hosts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Addresses { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Files { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Services { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Tasks { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Processes { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> RegistryPaths { get; init; } = Array.Empty<string>();

    public IReadOnlyList<int> Ports { get; init; } = Array.Empty<int>();

    public IReadOnlyList<uint> Pids { get; init; } = Array.Empty<uint>();

    public static QuestionEntities None { get; } = new();

    /// <summary>True when the question named anything in particular at all.</summary>
    public bool Any =>
        Hosts.Count > 0 || Addresses.Count > 0 || Files.Count > 0 || Services.Count > 0
        || Tasks.Count > 0 || Processes.Count > 0 || RegistryPaths.Count > 0
        || Ports.Count > 0 || Pids.Count > 0;

    /// <summary>Everything named, as plain strings, for matching against evidence rows.</summary>
    public IEnumerable<string> AllNames() =>
        Hosts.Concat(Addresses).Concat(Files).Concat(Services)
             .Concat(Tasks).Concat(Processes).Concat(RegistryPaths)
             .Concat(Ports.Select(static p => p.ToString(System.Globalization.CultureInfo.InvariantCulture)));

    /// <summary>
    /// The category this question is about, when what it names says so unambiguously.
    /// </summary>
    /// <remarks>
    /// Typing a bare host name after a conversation about services is a question about
    /// that host, not about services. The name carries the topic, so it is allowed to
    /// override a topic inherited from earlier — but only when exactly one category was
    /// named, because "does the service talk to example.com" names two and means the
    /// question, not the entities, decides.
    /// </remarks>
    public SessionQuestionKind? ImpliedKind()
    {
        var kinds = new List<SessionQuestionKind>();

        if (Hosts.Count > 0 || Addresses.Count > 0) kinds.Add(SessionQuestionKind.NetworkDestinations);
        if (Services.Count > 0) kinds.Add(SessionQuestionKind.Services);
        if (Tasks.Count > 0) kinds.Add(SessionQuestionKind.ScheduledTasks);
        if (Files.Count > 0) kinds.Add(SessionQuestionKind.FilesDropped);
        if (RegistryPaths.Count > 0) kinds.Add(SessionQuestionKind.RegistryChanges);
        if (Processes.Count > 0 || Pids.Count > 0) kinds.Add(SessionQuestionKind.ProcessesStarted);
        if (Ports.Count > 0) kinds.Add(SessionQuestionKind.Listeners);

        return kinds.Distinct().Count() == 1 ? kinds[0] : null;
    }
}

/// <summary>
/// The names a particular session contains, so a question can be matched against them.
/// </summary>
/// <remarks>
/// Built once per session and reused for every question. Names are held lowercase because
/// an operator types <c>windelay</c> for a service registered as <c>WinDelay</c>, and being
/// case-sensitive about that would be a bug reported as "it does not know its own data".
/// </remarks>
public sealed class SessionVocabulary
{
    private readonly Dictionary<string, string> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _services = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _tasks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _processes = new(StringComparer.OrdinalIgnoreCase);

    public void AddHost(string? name) => Add(_hosts, name);

    public void AddService(string? name) => Add(_services, name);

    public void AddTask(string? name) => Add(_tasks, name);

    public void AddProcess(string? name) => Add(_processes, name);

    /// <summary>
    /// Adds a file, indexed by its leaf name as well as its full path.
    /// </summary>
    /// <remarks>
    /// Nobody types a full path into a chat box. They type <c>msdatacomp64.dll</c>, and the
    /// answer has to find it.
    /// </remarks>
    public void AddFile(string? path)
    {
        Add(_files, path);
        if (string.IsNullOrWhiteSpace(path)) return;

        string leaf = path.Replace('/', '\\').TrimEnd('\\');
        int slash = leaf.LastIndexOf('\\');
        if (slash >= 0 && slash < leaf.Length - 1) Add(_files, leaf[(slash + 1)..]);
    }

    private static void Add(Dictionary<string, string> into, string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;

        // Short names match inside unrelated words and turn every question into a question
        // about them. Four characters is where that stops being a real risk in both
        // interface languages.
        string trimmed = name.Trim();
        if (trimmed.Length < 4) return;

        into.TryAdd(trimmed, trimmed);
    }

    // A bare host, an IPv4 literal, a Windows path or leaf file name, a registry path.
    private static readonly Regex HostPattern = new(
        @"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AddressPattern = new(
        @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", RegexOptions.Compiled);

    private static readonly Regex FilePattern = new(
        @"(?:[a-z]:\\|%[a-z0-9()]+%\\)?[^\s""'`,;]*\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jse|scr|msi|tmp|dat|sqlite|log)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RegistryPattern = new(
        @"\bHK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)(?:\\[^\s""'`,;]+)+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PortPattern = new(
        @"(?::(\d{1,5})\b)|(?:\b(?:port|bağlantı noktası)\s*[:=]?\s*(\d{1,5})\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PidPattern = new(
        @"\b(?:pid|process id|süreç kimliği|işlem kimliği)\s*[:=]?\s*(\d{1,7})\b|\((\d{2,7})\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public QuestionEntities Extract(string question)
    {
        if (string.IsNullOrWhiteSpace(question)) return QuestionEntities.None;

        var addresses = AddressPattern.Matches(question).Select(static m => m.Value).Distinct().ToList();
        var registry = RegistryPattern.Matches(question).Select(static m => m.Value).Distinct().ToList();

        var files = FilePattern.Matches(question)
            .Select(static m => m.Value)
            .Where(static v => v.Length > 4)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // An address is four numbers separated by dots and so is a host by the host
        // pattern; whichever it is, it is not both.
        var hosts = HostPattern.Matches(question)
            .Select(static m => m.Value)
            .Where(v => !addresses.Contains(v))
            .Where(v => !files.Contains(v, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var ports = new List<int>();
        foreach (Match m in PortPattern.Matches(question))
        {
            string raw = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            if (int.TryParse(raw, out int port) && port is > 0 and <= 65535) ports.Add(port);
        }

        var pids = new List<uint>();
        foreach (Match m in PidPattern.Matches(question))
        {
            string raw = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            if (uint.TryParse(raw, out uint pid) && pid > 0) pids.Add(pid);
        }

        return new QuestionEntities
        {
            Addresses = addresses,
            RegistryPaths = registry,

            // Names the session knows take precedence: a host in the vocabulary is a host
            // this session saw, and one that is not is still worth answering about.
            Hosts = Merge(hosts, Known(_hosts, question)),
            Files = Merge(files, Known(_files, question)),
            Services = Known(_services, question),
            Tasks = Known(_tasks, question),
            Processes = Known(_processes, question),
            Ports = ports.Distinct().ToList(),
            Pids = pids.Distinct().ToList(),
        };
    }

    private static List<string> Merge(List<string> found, List<string> known) =>
        known.Concat(found).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Names from the session that appear in the question.</summary>
    /// <remarks>
    /// Longest first, so asking about <c>msdatacomp64.dll</c> does not also report
    /// <c>msdatacomp64</c> as a separate thing when both are in the vocabulary.
    /// </remarks>
    private static List<string> Known(Dictionary<string, string> vocabulary, string question)
    {
        var hits = new List<string>();

        foreach (string name in vocabulary.Keys.OrderByDescending(static k => k.Length))
        {
            if (!question.Contains(name, StringComparison.OrdinalIgnoreCase)) continue;
            if (hits.Any(h => h.Contains(name, StringComparison.OrdinalIgnoreCase))) continue;
            hits.Add(vocabulary[name]);
        }

        return hits;
    }
}
