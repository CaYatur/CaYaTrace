using System.Globalization;

namespace CaYaTrace.App.Cli;

public sealed class CommandLineException : Exception
{
    public CommandLineException(string message) : base(message) { }
}

/// <summary>
/// Minimal argument parsing. Deliberately hand-written rather than pulled from a
/// package: the surface is a handful of verbs and flags, and a portable forensics
/// tool benefits from having fewer third-party components inside it.
/// </summary>
public sealed class CommandLine
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);

    public string Verb { get; private init; } = string.Empty;

    public IReadOnlyList<string> Positional { get; private init; } = Array.Empty<string>();

    public string[] Raw { get; private init; } = Array.Empty<string>();

    private static readonly HashSet<string> Verbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "trace", "report", "remediate", "compare", "explain", "agent", "version", "help",
    };

    public static CommandLine Parse(string[] args)
    {
        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        string verb = string.Empty;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg is "-h" or "--help" or "/?")
            {
                verb = "help";
                continue;
            }

            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                string name = arg[2..];
                string? value = null;

                int eq = name.IndexOf('=', StringComparison.Ordinal);
                if (eq >= 0)
                {
                    value = name[(eq + 1)..];
                    name = name[..eq];
                }
                else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    value = args[++i];
                }

                options[name] = value;
                continue;
            }

            if (verb.Length == 0 && Verbs.Contains(arg)) verb = arg.ToLowerInvariant();
            else positional.Add(arg);
        }

        var result = new CommandLine
        {
            Verb = verb,
            Positional = positional,
            Raw = args,
        };

        foreach ((string key, string? value) in options) result._options[key] = value;
        return result;
    }

    public bool Has(string name) => _options.ContainsKey(name);

    public string? Get(string name) => _options.GetValueOrDefault(name);

    public string Require(string name)
        => _options.GetValueOrDefault(name)
           ?? throw new CommandLineException($"--{name} is required");

    public bool Flag(string name, bool fallback = false)
    {
        if (!_options.TryGetValue(name, out string? value)) return fallback;
        return value is null
            || value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value == "1";
    }

    public int Int(string name, int fallback)
        => _options.TryGetValue(name, out string? value)
           && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : fallback;

    public static int PrintUsage()
    {
        Console.WriteLine($"""
            CaYaTrace {BuildInfo.Version} — Windows application forensics

            USAGE
              CaYaTrace                                Open the analyst workbench
              CaYaTrace trace  [options]               Record a session headlessly
              CaYaTrace report [options]               Render a recorded session
              CaYaTrace remediate [options]            Apply a removal package
              CaYaTrace compare <dirA> <dirB> [...]   Compare recordings from several machines
              CaYaTrace explain [options]              Rank and explain a session's findings
              CaYaTrace agent  [options]               Run as a fleet collection agent
              CaYaTrace version

            GLOBAL
              --lang <en|tr>         Interface language. Defaults to the system language
                                     when CaYaTrace has it, otherwise English.

            WORKBENCH
              --session <dir|file>   Open this session on startup
              --view <name>          Open on a section: overview, capture, sessions,
                                     findings, tree, network, compare, assistant,
                                     remediate, fleet

            TRACE
              --target <path>        Program to launch and observe
              --args <string>        Arguments passed to the target
              --attach <pid>         Observe an already-running process instead
              --system-wide          Observe everything; decide scope afterwards
              --duration <seconds>   Stop automatically after this long
              --out <dir>            Session root directory (default ./sessions)
              --no-snapshots         Skip before/after system inventories
              --reads                Also record read operations (much higher volume)
              --buffer-mb <n>        ETW buffer pool size (default 256)
              --scoped-only          Discard activity outside the target's process tree
              --packets              Capture packets with the Windows packet monitor,
                                     converted to pcapng for Wireshark and correlated
                                     back to processes by 5-tuple
              --packet-cap-mb <n>    Circular capture size cap (default 512)
              --intercept-https      Ask to intercept HTTPS. Installs a temporary
                                     certificate authority into the machine's trusted
                                     roots for the length of the session, so request and
                                     response bodies become readable. Asks first, and
                                     removes it afterwards. Use a disposable VM.
              --intercept-https-consent
                                     Consent without the interactive prompt, for sandbox
                                     automation. Same effect, same cleanup; you are
                                     agreeing on the operator's behalf.

            REPORT
              --session <dir|file>   Session to render
              --format <fmt>         tree | json | html | csv    (default tree)
              --scope <level>        minimal | standard | full   (default standard)
                                     minimal is findings only, for a reader who will
                                     not open a tree; full includes reads and activity
                                     never attributed to the subject.
              --categories <list>    Comma-separated category filter
              --out <path>           Write to a file instead of stdout
                                     Required for html and csv.
              --include-reads        Include read operations in the tree
              --export-package <f>   Write a removal package instead of a report

            REMEDIATE
              --package <file.ctpkg> Removal package to apply
              --dry-run              Show the plan without changing anything (default)
              --apply                Actually perform the removal
              --quarantine <dir>     Where removed items are moved (default ./quarantine)

            COMPARE
              <dirA> <dirB> ...      Sessions of the same program from different machines
              --export-package <f>   Write a removal package using measured path patterns
              --min-origins <n>      Only include artifacts seen on at least this many
                                     machines (default: all of them)

              Comparing two machines is what turns a guessed path pattern into a
              measured one, so a package built here still matches on a third machine
              that names its random directories differently again.

            EXPLAIN
              --session <dir|file>   Session to explain
              --model <name>         Local Ollama model to label findings with (optional)
              --check-models         Score every installed model and recommend one
              --ollama <url>         Ollama endpoint (default http://localhost:11434)
              --max-findings <n>     How many top-ranked artifacts to include (default 30)
              --virustotal           Look up dropped executables by hash (needs
                                     CAYATRACE_VT_API_KEY). Hash lookup only — CaYaTrace
                                     never uploads a file, because submitting a sample
                                     publishes it permanently.

              Ranking, scoring, and the reasons behind them are CaYaTrace's own rules and
              need no model. A model only adds a label per artifact, is tested against
              known answers before it is believed, and has its answers checked against
              the rules. Run --check-models first: small and coder-tuned models score
              poorly at this, and knowing that beats reading their guesses.

            AGENT
              --host <addr:port>     Host to report to once paired
              --pair <code>          One-time pairing code issued by the host
              --out <dir>            Where the agent records locally (default ./sessions)

              The agent connects out and then does nothing until the host approves it,
              so running one does not give that machine a remote entry point. Both
              values are shown in the workbench's Fleet tab on the host machine.

              Packet capture and HTTPS interception cannot be started remotely. Both
              change the machine they run on, and a host that could trigger them would
              turn a paired agent into a remote administration channel.

            Kernel tracing requires an elevated process. Everything else does not.

            Authorized use only. Captured sessions can contain credentials, tokens,
            cookies, and personal data. See SECURITY.md.
            {BuildInfo.Repository}
            """);
        return 0;
    }
}
