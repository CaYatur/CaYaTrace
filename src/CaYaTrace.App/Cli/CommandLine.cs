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
        "trace", "report", "remediate", "agent", "version", "help",
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
              CaYaTrace agent  [options]               Run as a fleet collection agent
              CaYaTrace version

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

            REPORT
              --session <dir|file>   Session to render
              --format <fmt>         tree | json | html | csv    (default tree)
              --categories <list>    Comma-separated category filter
              --out <path>           Write to a file instead of stdout
              --include-reads        Include read operations in the tree

            REMEDIATE
              --package <file.ctpkg> Removal package to apply
              --dry-run              Show the plan without changing anything (default)
              --apply                Actually perform the removal
              --quarantine <dir>     Where removed items are moved (default ./quarantine)

            AGENT
              --host <addr:port>     Host to report to once paired
              --pair <code>          One-time pairing code issued by the host
              --listen <port>        Accept an inbound host connection instead

            Kernel tracing requires an elevated process. Everything else does not.

            Authorized use only. Captured sessions can contain credentials, tokens,
            cookies, and personal data. See SECURITY.md.
            {BuildInfo.Repository}
            """);
        return 0;
    }
}
