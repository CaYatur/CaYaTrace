using System.Globalization;
using System.Net;
using System.Text;
using CaYaTrace.Core.Model;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace CaYaTrace.Collectors.Etw;

public sealed class NetworkCollectorOptions
{
    /// <summary>Record DNS queries and their answers.</summary>
    public bool CollectDns { get; init; } = true;

    /// <summary>Record URLs from applications using the Windows HTTP stacks.</summary>
    public bool CollectHttpStacks { get; init; } = true;

    /// <summary>Record TLS handshake metadata from Schannel.</summary>
    public bool CollectTls { get; init; } = true;

    public int BufferSizeMB { get; init; } = 64;

    public static NetworkCollectorOptions Default { get; } = new();
}

/// <summary>
/// Name resolution, TLS metadata, and URLs from the Windows HTTP stacks.
/// </summary>
/// <remarks>
/// <para>
/// This is the non-invasive half of network visibility: it changes nothing on the
/// machine, touches no certificate store, and works for every application — but it
/// sees only what the OS layers report. Full request and response bodies need the
/// intercepting proxy, which is a separate, opt-in decision.
/// </para>
/// <para>
/// Its main job in the causal tree is turning bare addresses into names. A connection
/// to <c>172.217.114.4:443</c> tells an analyst almost nothing; the same connection
/// annotated <c>api.example.com</c> is the finding.
/// </para>
/// </remarks>
public sealed class NetworkCollector : ICollector
{
    // These providers are user-mode and manifest-based, so they need their own
    // session: the kernel session accepts only kernel keywords.
    private const string DnsProvider = "Microsoft-Windows-DNS-Client";
    private const string WinINetProvider = "Microsoft-Windows-WinINet";
    private const string WinHttpProvider = "Microsoft-Windows-WinHttp";
    private const string SchannelProvider = "Microsoft-Windows-Schannel-Events";

    /// <summary>
    /// DNS query started, carrying the requesting process.
    /// </summary>
    /// <remarks>
    /// Deliberately 3016 rather than the widely cited 3006. Both describe a query, but
    /// only 3016 carries <c>ClientPID</c>. This matters because DNS resolution runs inside
    /// the dnscache service: the event's own <c>ProcessID</c> is svchost, so attributing on
    /// it would credit every lookup on the machine to a Windows service instead of to
    /// the program that asked. Verified by enumerating the provider's actual payloads
    /// on Windows 11 26H1.
    /// </remarks>
    private const int DnsQueryWithPid = 3016;

    /// <summary>DNS query completed, with results and the requesting process.</summary>
    private const int DnsResponseWithPid = 3018;

    private readonly NetworkCollectorOptions _options;
    private readonly string _sessionName;

    private TraceEventSession? _session;
    private Task? _processing;
    private CollectorContext? _ctx;
    private volatile bool _stopping;

    private long _dnsQueries;
    private long _httpRequests;
    private long _tlsHandshakes;

    public NetworkCollector(NetworkCollectorOptions? options = null, string? sessionName = null)
    {
        _options = options ?? NetworkCollectorOptions.Default;
        _sessionName = sessionName ?? $"CaYaTrace-Net-{Environment.ProcessId}";
    }

    public string Name => "network-etw";

    public bool RequiresElevation => true;

    public Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        if (!TraceEventSession.IsElevated().GetValueOrDefault())
        {
            context.ReportSkipped(Name, "user-mode network tracing requires an elevated process");
            return Task.FromResult(false);
        }

        try
        {
            _session = new TraceEventSession(_sessionName)
            {
                BufferSizeMB = _options.BufferSizeMB,
                StopOnDispose = true,
            };

            int enabled = 0;
            if (_options.CollectDns) enabled += Enable(DnsProvider);
            if (_options.CollectHttpStacks)
            {
                enabled += Enable(WinINetProvider);
                enabled += Enable(WinHttpProvider);
            }
            if (_options.CollectTls) enabled += Enable(SchannelProvider);

            if (enabled == 0)
            {
                context.ReportSkipped(Name, "no user-mode network providers were available");
                return Task.FromResult(false);
            }

            Subscribe(context);

            _processing = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) when (!_stopping)
                {
                    context.ReportFault(Name, "network trace processing stopped unexpectedly", ex);
                }
            }, CancellationToken.None);

            context.Session.EnabledCollectors.Add(Name);
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            context.ReportFault(Name, "could not start the network session", ex);
            return Task.FromResult(false);
        }
    }

    private int Enable(string providerName)
    {
        Guid guid = TraceEventProviders.GetProviderGuidByName(providerName);
        if (guid == Guid.Empty)
        {
            // Not every provider exists on every SKU. A missing one is worth recording
            // but is not a failure of the collector.
            _ctx?.Store.LogQuality(Name, "info", $"{providerName} is not registered on this machine");
            return 0;
        }

        _session!.EnableProvider(guid, TraceEventLevel.Informational, ulong.MaxValue);
        return 1;
    }

    private void Subscribe(CollectorContext ctx)
    {
        _session!.Source.Dynamic.All += e =>
        {
            switch (e.ProviderName)
            {
                case DnsProvider:
                    OnDns(ctx, e);
                    break;
                case WinINetProvider:
                case WinHttpProvider:
                    OnHttpStack(ctx, e);
                    break;
                case SchannelProvider:
                    OnSchannel(ctx, e);
                    break;
            }
        };
    }

    // ------------------------------------------------------------------- DNS

    private void OnDns(CollectorContext ctx, TraceEvent e)
    {
        int id = (int)e.ID;
        if (id is not (DnsQueryWithPid or DnsResponseWithPid)) return;

        string? queryName = e.PayloadStringByName("QueryName");
        if (string.IsNullOrWhiteSpace(queryName)) return;

        queryName = queryName.TrimEnd('.');

        // ClientPID is the requesting process; the event's own ProcessID is dnscache.
        ProcessKey actor = ProcessKey.None;
        if (TryGetUInt(e, "ClientPID", out uint clientPid) && clientPid != 0)
            actor = ctx.Processes.Resolve(clientPid, e.TimeStamp);

        if (id == DnsQueryWithPid)
        {
            Interlocked.Increment(ref _dnsQueries);
            ctx.Emit(new Observation
            {
                Timestamp = e.TimeStamp,
                Category = EventCategory.Dns,
                Action = EventAction.DnsQuery,
                Actor = actor,
                Target = queryName,
                Target2 = DescribeQueryType(e.PayloadStringByName("QueryType")),
                Source = EvidenceSource.UserEtw,
                Confidence = actor == ProcessKey.None ? AttributionConfidence.None : AttributionConfidence.Direct,
                Status = EventStatus.Pending,
            });
            return;
        }

        string? status = e.PayloadStringByName("Status") ?? e.PayloadStringByName("QueryStatus");
        string? results = e.PayloadStringByName("QueryResults");
        List<IPAddress> addresses = ParseAddresses(results);

        // Tagging flows retroactively is what turns a bare address in the tree into a
        // hostname. Done here rather than at render time because the mapping is only
        // sound within the window the answer was valid for.
        foreach (IPAddress address in addresses)
            ctx.Flows.NoteDnsAnswer(address, queryName, e.TimeStamp);

        bool ok = status is null || status is "0" || status.Equals("SUCCESS", StringComparison.OrdinalIgnoreCase);

        ctx.Emit(new Observation
        {
            Timestamp = e.TimeStamp,
            Category = EventCategory.Dns,
            Action = EventAction.DnsResponse,
            Actor = actor,
            Target = queryName,
            Target2 = addresses.Count > 0 ? string.Join(", ", addresses.Select(static a => a.ToString())) : null,
            NewValue = results,
            Source = EvidenceSource.UserEtw,
            Confidence = actor == ProcessKey.None ? AttributionConfidence.None : AttributionConfidence.Direct,
            Status = ok ? EventStatus.Success : EventStatus.Failed,
        });
    }

    /// <summary>
    /// Extracts addresses from the provider's answer string.
    /// </summary>
    /// <remarks>
    /// The field is a semicolon-separated record list mixing address records with CNAME
    /// entries and type prefixes, for example
    /// <c>type: 5 alias.example.com;::ffff:93.184.216.34;</c>. Only the parts that parse
    /// as an address are taken; anything else is left to the raw payload, which is
    /// preserved on the observation.
    /// </remarks>
    internal static List<IPAddress> ParseAddresses(string? queryResults)
    {
        var addresses = new List<IPAddress>();
        if (string.IsNullOrWhiteSpace(queryResults)) return addresses;

        foreach (string part in queryResults.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string candidate = part;

            // Strip a "type: N " prefix when present.
            int space = candidate.LastIndexOf(' ');
            if (candidate.StartsWith("type:", StringComparison.OrdinalIgnoreCase) && space > 0)
                candidate = candidate[(space + 1)..];

            if (!IPAddress.TryParse(candidate, out IPAddress? address)) continue;

            // IPv4 answers are reported IPv4-mapped; unmapping keeps them comparable
            // with the addresses the kernel network provider reports.
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            addresses.Add(address);
        }

        return addresses;
    }

    private static string DescribeQueryType(string? queryType)
        => queryType switch
        {
            "1" => "A",
            "2" => "NS",
            "5" => "CNAME",
            "6" => "SOA",
            "12" => "PTR",
            "15" => "MX",
            "16" => "TXT",
            "28" => "AAAA",
            "33" => "SRV",
            "65" => "HTTPS",
            null => string.Empty,
            _ => $"type {queryType}",
        };

    // ------------------------------------------------------------------ HTTP

    /// <summary>
    /// Captures URLs from applications using WinINet or WinHTTP.
    /// </summary>
    /// <remarks>
    /// Covers a large share of Windows software — installers, updaters, background
    /// services, anything built on the platform stacks — with no certificate authority
    /// and no proxy. It does <em>not</em> cover applications that ship their own TLS stack,
    /// which includes the major browsers; those need the opt-in proxy.
    ///
    /// The events are matched by payload shape rather than by event id, because the
    /// two providers number their events differently and both have changed numbering
    /// across Windows releases.
    /// </remarks>
    private void OnHttpStack(CollectorContext ctx, TraceEvent e)
    {
        string? url = FirstPayload(e, "Url", "URL", "RequestUrl", "ObjectUri", "Uri");
        if (string.IsNullOrWhiteSpace(url)) return;

        string? method = FirstPayload(e, "Verb", "Method", "RequestMethod");
        string? statusText = FirstPayload(e, "StatusCode", "Status", "HttpStatusCode");

        bool isResponse = statusText is { Length: > 0 }
                          || e.EventName.Contains("Response", StringComparison.OrdinalIgnoreCase)
                          || e.EventName.Contains("ResponseHeader", StringComparison.OrdinalIgnoreCase);

        ProcessKey actor = e.ProcessID > 0
            ? ctx.Processes.Resolve((uint)e.ProcessID, e.TimeStamp)
            : ProcessKey.None;

        long bytes = 0;
        if (TryGetUInt(e, "Length", out uint length)) bytes = length;
        else if (TryGetUInt(e, "ContentLength", out uint contentLength)) bytes = contentLength;

        Interlocked.Increment(ref _httpRequests);

        ctx.Emit(new Observation
        {
            Timestamp = e.TimeStamp,
            Category = EventCategory.Http,
            Action = isResponse ? EventAction.HttpResponse : EventAction.HttpRequest,
            Actor = actor,
            ThreadId = (uint)Math.Max(0, e.ThreadID),
            Target = url,
            Target2 = isResponse ? statusText : (method ?? "GET"),
            NewValue = isResponse ? statusText : null,
            Bytes = bytes,
            Source = EvidenceSource.UserEtw,
            Confidence = actor == ProcessKey.None ? AttributionConfidence.None : AttributionConfidence.Direct,
            Status = EventStatus.Success,
            Details = BuildDetails(e),
        });
    }

    // --------------------------------------------------------------- Schannel

    private void OnSchannel(CollectorContext ctx, TraceEvent e)
    {
        string? target = FirstPayload(e, "TargetName", "ServerName", "SNI", "HostName");
        string? protocol = FirstPayload(e, "Protocol", "ProtocolVersion", "TlsVersion");
        string? cipher = FirstPayload(e, "CipherSuite", "Cipher");

        if (string.IsNullOrWhiteSpace(target) && string.IsNullOrWhiteSpace(protocol)) return;

        ProcessKey actor = e.ProcessID > 0
            ? ctx.Processes.Resolve((uint)e.ProcessID, e.TimeStamp)
            : ProcessKey.None;

        Interlocked.Increment(ref _tlsHandshakes);

        ctx.Emit(new Observation
        {
            Timestamp = e.TimeStamp,
            Category = EventCategory.Tls,
            Action = EventAction.TlsHandshakeComplete,
            Actor = actor,
            Target = string.IsNullOrWhiteSpace(target) ? "(unnamed peer)" : target,
            Target2 = protocol,
            NewValue = cipher,
            Source = EvidenceSource.UserEtw,
            Confidence = actor == ProcessKey.None ? AttributionConfidence.None : AttributionConfidence.Direct,
            Status = EventStatus.Success,
            Details = BuildDetails(e),
        });
    }

    // ---------------------------------------------------------------- helpers

    private static string? FirstPayload(TraceEvent e, params string[] names)
    {
        string[] available = e.PayloadNames ?? Array.Empty<string>();
        foreach (string name in names)
        {
            if (!available.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            string? value = e.PayloadStringByName(name);
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }

    private static bool TryGetUInt(TraceEvent e, string name, out uint value)
    {
        value = 0;
        string[] available = e.PayloadNames ?? Array.Empty<string>();
        if (!available.Contains(name, StringComparer.OrdinalIgnoreCase)) return false;

        object? raw = e.PayloadByName(name);
        return raw switch
        {
            uint u => (value = u) >= 0,
            int i when i >= 0 => (value = (uint)i) >= 0,
            ulong ul => (value = (uint)ul) >= 0,
            long l when l >= 0 => (value = (uint)l) >= 0,
            string s => uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value),
            _ => false,
        };
    }

    /// <summary>
    /// Preserves the provider's full payload. These providers vary across Windows
    /// releases, so keeping the raw fields means a session recorded today stays
    /// interpretable even where this build only understood part of it.
    /// </summary>
    private static string? BuildDetails(TraceEvent e)
    {
        string[] names = e.PayloadNames ?? Array.Empty<string>();
        if (names.Length == 0) return null;

        var sb = new StringBuilder(128);
        sb.Append('{');
        for (int i = 0; i < names.Length; i++)
        {
            string? value = e.PayloadStringByName(names[i]);
            if (string.IsNullOrEmpty(value)) continue;
            if (sb.Length > 1) sb.Append(',');
            sb.Append(System.Text.Json.JsonSerializer.Serialize(names[i]))
              .Append(':')
              .Append(System.Text.Json.JsonSerializer.Serialize(value.Length > 512 ? value[..512] : value));
        }
        sb.Append('}');
        return sb.Length <= 2 ? null : sb.ToString();
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;

        if (_ctx is not null && _session is not null)
        {
            int lost = 0;
            try { lost = _session.EventsLost; }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { }
            _ctx.Quality.EventsLost += lost;

            _ctx.Store.LogQuality(Name, "info",
                $"dns={Interlocked.Read(ref _dnsQueries)} http={Interlocked.Read(ref _httpRequests)} " +
                $"tls={Interlocked.Read(ref _tlsHandshakes)}");
        }

        try { _session?.Stop(); }
        catch (Exception ex) { _ctx?.ReportFault(Name, "failed to stop the network session cleanly", ex); }

        if (_processing is not null)
        {
            await Task.WhenAny(_processing, Task.Delay(TimeSpan.FromSeconds(15), cancellationToken))
                .ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stopping)
        {
            try { await StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception) { /* disposal must not throw */ }
        }
        _session?.Dispose();
    }
}
