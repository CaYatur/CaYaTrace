using CaYaTrace.Core.Model;
using CaYaTrace.Remediation;
using CaYaTrace.Storage;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// Measures the planner against a real recording, when one is to hand.
/// </summary>
/// <remarks>
/// Skipped unless <c>CAYATRACE_SESSION</c> points at a <c>.ctdb</c>. It exists because
/// every genuine defect in this planner was found by running it over a real session and
/// reading the output, and none were found by reasoning about the code.
/// </remarks>
public sealed class RealSessionProbe
{
    private readonly ITestOutputHelper _out;

    public RealSessionProbe(ITestOutputHelper output) => _out = output;

    [Fact]
    public void MeasureEveryCombinationOfOptions()
    {
        if (Environment.GetEnvironmentVariable("CAYATRACE_SESSION") is not { Length: > 0 } path
            || !File.Exists(path))
        {
            _out.WriteLine("set CAYATRACE_SESSION=<path to session.ctdb> to run this");
            return;
        }

        using SessionStore store = SessionStore.Open(path);
        SessionInfo session = store.LoadSessionInfo()!;

        _out.WriteLine($"{session.Name}  root={session.RootProcess}  target={session.TargetPath}");
        _out.WriteLine(new string('-', 78));

        foreach (bool scoped in new[] { true, false })
        foreach (bool temp in new[] { true, false })
        {
            var options = new RemovalPlannerOptions
            {
                ScopedOnly = scoped,
                ExcludeTemporary = temp,
                IncludeModifiedFiles = false,
            };

            var planner = new RemovalPlanner(store, options: options);
            List<RemovalItem> plan = planner.Build(session);

            string label = $"scoped={scoped,-5} excludeTemp={temp,-5}";
            _out.WriteLine($"{label}  items={plan.Count,-6} excluded={planner.Excluded.Count}");

            foreach (IGrouping<RemovalKind, RemovalItem> group in plan.GroupBy(static i => i.Kind))
                _out.WriteLine($"        {group.Key,-14} {group.Count()}");
        }

        _out.WriteLine(new string('-', 78));

        var shipped = new RemovalPlanner(store, options: new RemovalPlannerOptions());
        foreach (RemovalItem item in shipped.Build(session))
            _out.WriteLine($"{item.Kind,-14} {item.Target}    [{item.Rationale}]");

        _out.WriteLine(new string('-', 78));
        _out.WriteLine($"program directory: {shipped.Footprint.Directory}");
        _out.WriteLine($"rejected as loader search probes ({shipped.Footprint.SearchProbes.Count}):");
        foreach (string probe in shipped.Footprint.SearchProbes) _out.WriteLine($"        {probe}");
    }
}
