using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CaYaTrace.Analysis;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.Export;

/// <summary>
/// Turns a stored session into the single JSON payload every view renders from.
/// </summary>
/// <remarks>
/// <para>
/// One projection, three consumers: the live workbench, the exported HTML report, and
/// the JSON export. They cannot disagree about what a session contains because there is
/// only one place that decides.
/// </para>
/// <para>
/// The projection is where "what the analyst reads" is separated from "what was
/// recorded". A session holds millions of rows; this produces the tens of thousands
/// worth putting in front of a person, ranked, and says so explicitly when it truncated
/// rather than letting a capped list read as a complete one.
/// </para>
/// </remarks>
public static class SessionProjection
{
    /// <summary>
    /// Enums are written as names, never ordinals.
    /// </summary>
    /// <remarks>
    /// Two reasons, both learned the hard way. The view keys category colours off these
    /// values, so <c>"Category": 3</c> is a silent lookup miss that renders as a bare
    /// number. And an exported JSON file is read by people and by other tools, where an
    /// ordinal that shifts when an enum member is inserted is a data-corruption bug that
    /// nothing detects.
    /// </remarks>
    public static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string Build(SessionStore store, SessionInfo session, ExportRequest request)
        => JsonSerializer.Serialize(BuildModel(store, session, request), Json);

    public static object BuildModel(SessionStore store, SessionInfo session, ExportRequest request)
    {
        var processes = new ProcessTable();
        List<ProcessNode> nodes = store.LoadProcesses();
        foreach (ProcessNode node in nodes) processes.AddOrUpdate(node);

        var flows = new FlowTable();
        List<NetworkFlow> storedFlows = store.LoadFlows();
        foreach (NetworkFlow flow in storedFlows)
            flows.NoteConnect(flow.Key, flow.Owner, flow.FirstSeen, flow.OwnerEvidence ?? "stored");

        var byKey = new Dictionary<ProcessKey, ProcessNode>();
        foreach (ProcessNode node in nodes) byKey.TryAdd(node.Key, node);

        var inScope = new HashSet<ProcessKey>(nodes.Where(static p => p.InScope).Select(static p => p.Key));

        // A system-wide recording has no subject, so nothing is marked in scope — and
        // "narrow this to the subject" then narrows it to nothing. Measured: a 33,811
        // event capture reported zero findings, because every attributed observation was
        // outside a scope that did not exist. Scope only means something when there is
        // something to be outside of.
        bool scoped = inScope.Count > 0;

        bool Included(Observation o) =>
            request.Allows(o.Category)
            && (!scoped || request.IncludeOutOfScope || o.Actor == ProcessKey.None || inScope.Contains(o.Actor));

        // Findings are computed from the same rules the CLI uses, and deliberately
        // without a model: an exported report must be reproducible by anyone who opens
        // it, and must never imply a model saw data it did not.
        //
        // The process table is handed in because two of the rules — whether a
        // cross-process thread is Windows going about its business, and whether a write
        // into an OS-managed cache is the OS doing it — turn on who signed the code, and
        // that is only knowable from the process record.
        IReadOnlyList<ScoredArtifact> findings = new ArtifactScorer(processLookup: byKey.GetValueOrDefault)
            .TopFindings(store.Query().Where(Included), request.FindingLimit);

        object[] tree = request.IncludeTree
            ? BuildTree(store, session, processes, flows, request)
            : Array.Empty<object>();

        // Persistence is computed over everything, not over the filtered stream. An entry
        // that survives a reboot is the single most important thing a session can find,
        // and narrowing the input to the subject's own process tree would lose the ones
        // installed by a helper the subject launched and then stopped.
        IReadOnlyList<PersistenceRecord> persistence = new PersistenceAnalyzer(byKey.GetValueOrDefault)
            .Analyze(store.Query());

        return new
        {
            generated = DateTimeOffset.UtcNow,
            language = request.Language,
            scope = request.Scope.ToString(),
            session,
            counts = store.CountByCategory()
                .Where(static kv => kv.Key != EventCategory.Session)
                .ToDictionary(static kv => kv.Key.ToString(), static kv => kv.Value),
            totalObservations = store.CountObservations(),
            findings = findings.Select(Project).ToList(),
            persistence = persistence.Select(r => ProjectPersistence(r, byKey)).ToList(),
            timeline = new ProcessTimeline()
                .Build(nodes, store.Query(), persistence, session.RootProcess)
                .Select(static e => new
                {
                    pid = e.Pid,
                    parent = e.ParentPid,
                    name = e.Name,
                    path = e.Path,
                    commandLine = e.CommandLine,
                    user = e.User,
                    started = e.Started,
                    exited = e.Exited,
                    exitCode = e.ExitCode,
                    seconds = e.Lifetime?.TotalSeconds,
                    depth = e.Depth,
                    inScope = e.InScope,
                    preExisting = e.PreExisting,
                    elevated = e.IsElevated,
                    signature = e.Signature.ToString(),
                    signer = e.Signer,
                    sha256 = e.Sha256,
                    files = e.FilesWritten,
                    registry = e.RegistryChanges,
                    modules = e.ModulesLoaded,
                    connections = e.Connections,
                    children = e.ChildrenStarted,
                    installed = e.Installed,
                    notes = e.Notes,
                })
                .ToList(),
            tree,
            network = BuildNetwork(store, byKey, inScope, storedFlows, request),
            processes = nodes
                .OrderBy(static p => p.StartTime)
                .Take(request.Scope == ExportScope.Full ? int.MaxValue : 2_000)
                .Select(static p => new
                {
                    key = p.Key,
                    pid = p.Pid,
                    parent = p.ParentKey,
                    name = p.ImageName,
                    path = p.ImagePath,
                    commandLine = p.CommandLine,
                    user = p.UserName,
                    started = p.StartTime,
                    exited = p.ExitTime,
                    exitCode = p.ExitCode,
                    inScope = p.InScope,
                    signature = p.Signature.ToString(),
                    signer = p.Signer,
                    sha256 = p.Sha256,
                })
                .ToList(),
        };
    }

    private static object[] BuildTree(
        SessionStore store, SessionInfo session, ProcessTable processes, FlowTable flows, ExportRequest request)
    {
        var options = new CausalGraphOptions
        {
            IncludeReads = request.IncludeReads,
            IncludeOutOfScope = request.IncludeOutOfScope,
            MaxArtifactsPerGroup = request.MaxArtifactsPerGroup,

            // Anchor on the subject, so the tree does not open on the shell that
            // happened to launch the tool.
            RootProcess = session.RootProcess == ProcessKey.None ? null : session.RootProcess,
        };

        var query = new ObservationQuery
        {
            Categories = request.Categories?.ToList(),
        };

        return new CausalGraphBuilder(processes, flows)
            .Build(store.Query(query), options)
            .Cast<object>()
            .ToArray();
    }

    /// <summary>
    /// One way the subject arranged to run again, with everything known about it.
    /// </summary>
    /// <remarks>
    /// The values are carried in full rather than summarised. A service entry that names
    /// only its image path is the shape this used to have, and it is the shape that let a
    /// comparison tool describe the same service better than we could from the same
    /// evidence: the display name, start type, account and recovery actions were all
    /// recorded and none of them reached the reader.
    /// </remarks>
    private static object ProjectPersistence(
        PersistenceRecord record, Dictionary<ProcessKey, ProcessNode> byKey) => new
    {
        kind = record.Kind.ToString(),
        identity = record.Identity,
        location = record.Location,
        command = record.Command,
        displayName = record.DisplayName,
        risk = record.Risk.ToString(),
        score = record.Score,
        traits = record.Traits,
        reasons = record.Reasons,
        isNew = record.IsNew,
        restartsItself = record.RestartsItself,
        firstSeen = record.FirstSeen == default ? (DateTimeOffset?)null : record.FirstSeen,
        installedBy = record.Actor == ProcessKey.None
            ? null
            : byKey.TryGetValue(record.Actor, out ProcessNode? node) ? node.ImageName : $"pid {record.Actor.Pid}",
        source = record.Source.ToString(),
        confidence = record.Confidence.ToString(),
        values = record.Values.Select(static v => new
        {
            name = v.Name,
            data = v.Data,
            previous = v.Previous,
            source = v.Source.ToString(),
        }).ToList(),
    };

    /// <summary>
    /// The conversations reassembled from the packet capture, with what they carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Separate from the flow table because it answers a different question. Flows say
    /// which endpoints exchanged how many bytes; a conversation says whether this machine
    /// called out or something called in, whether the peer is on the internet or on the
    /// same network, what protocol was actually spoken, and where to find the bytes.
    /// </para>
    /// <para>
    /// The peer scope is the reason this exists at all. Traffic to the internet is what
    /// every tool shows; a program talking to another machine on the local network, or to
    /// a second copy of itself, is how software coordinates with its own components — and
    /// it appears in no firewall log, no proxy, and no HTTP stack.
    /// </para>
    /// </remarks>
    private static List<object> BuildConversations(
        SessionStore store,
        Dictionary<ProcessKey, ProcessNode> byKey,
        Func<ProcessKey, bool> owned,
        ExportRequest request)
    {
        var result = new List<object>();
        if (!request.Allows(EventCategory.Network)) return result;

        foreach (Observation o in store.Query(new ObservationQuery
                 {
                     Categories = new List<EventCategory> { EventCategory.Network },
                 }))
        {
            if (result.Count >= request.NetworkRowLimit) break;
            if (!owned(o.Actor)) continue;
            if (o.Details is not { Length: > 0 } details) continue;

            // Two sources produce conversations and both belong here: the packet capture,
            // which carries contents for traffic that crossed an adapter, and Winsock,
            // which is the only thing that sees traffic that never left the machine.
            if (o.Source != EvidenceSource.PacketCapture
                && !details.Contains("\"via\":\"winsock\"", StringComparison.Ordinal))
            {
                continue;
            }

            JsonElement facts;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(details);
                facts = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue;
            }

            result.Add(new
            {
                seq = o.Seq,
                when = o.Timestamp,
                process = o.Actor == ProcessKey.None
                    ? null
                    : byKey.TryGetValue(o.Actor, out ProcessNode? node) ? node.ImageName : $"pid {o.Actor.Pid}",
                pid = o.Actor.Pid,
                peer = o.Target,
                name = o.Target2,
                summary = o.NewValue,
                bytes = o.Bytes,
                scope = Text(facts, "scope"),
                protocol = Text(facts, "protocol"),
                localPort = Number(facts, "localPort"),
                inbound = Flag(facts, "inbound"),
                truncated = Flag(facts, "truncated"),

                // The hash finds the full bytes in the session; the preview travels with
                // the report. An exported report has no engine behind it, so a hash alone
                // gave the reader a button that reached nothing — measured, in an export
                // somebody actually tried to read.
                sentBody = Text(facts, "sentBody"),
                receivedBody = Text(facts, "receivedBody"),
                sentBytes = Number(facts, "sentBytes"),
                receivedBytes = Number(facts, "receivedBytes"),
                sentPreview = Preview(store, Text(facts, "sentBody"), request),
                receivedPreview = Preview(store, Text(facts, "receivedBody"), request),
                confidence = o.Confidence.ToString(),
                evidence = Text(facts, "evidence"),

                // Who is at the other end, for conversations that never left the machine.
                // Their contents cannot be captured, so naming the program being talked
                // to is most of the answer that is available.
                peerProcess = Text(facts, "peerProcess"),
                contentsUnavailable = Flag(facts, "contentsUnavailable"),
                via = Text(facts, "via") ?? "packets",
            });
        }

        return result;
    }

    /// <summary>
    /// The beginning of a stored conversation body, as readable text.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carried in the projection so an exported report can show it. The live workbench
    /// can fetch the whole thing on demand; a report opened on another machine has
    /// nothing to fetch from, and a button that reaches nothing is worse than no button.
    /// </para>
    /// <para>
    /// Bounded hard, and only at full scope. A session can hold thousands of
    /// conversations and inlining all of them would turn a report into something nobody
    /// can open — and every byte of it came off the wire, so a report carrying more of it
    /// is a report that leaks more if it is shared carelessly.
    /// </para>
    /// </remarks>
    private static string? Preview(SessionStore store, string? hash, ExportRequest request)
    {
        // Enough to hold a request and its headers, a handshake, or a beacon, which is
        // what these conversations almost always are.
        const int Bytes = 8192;

        // Everything except the deliberately cut-down report. This used to require the
        // full scope, so the default export carried byte counts and nothing else and the
        // buttons that open a body were disabled — an operator looking at their own
        // exported report could see that a program sent 6.6 KB to an address and had no
        // way to find out what was in it. Volume is what the scopes are for; contents are
        // the reason a conversation was recorded at all.
        if (request.Scope == ExportScope.Minimal) return null;
        if (hash is not { Length: 64 }) return null;

        byte[]? body;
        try { body = store.ReadBlob(hash); }
        catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException) { return null; }

        if (body is null || body.Length == 0) return null;

        byte[] slice = body.Length <= Bytes ? body : body[..Bytes];
        return IsMostlyText(slice)
            ? new UTF8Encoding(false, false).GetString(slice)
            : HexDump(slice);
    }

    private static bool IsMostlyText(byte[] data)
    {
        int length = Math.Min(data.Length, 512);
        int printable = 0;

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b is 9 or 10 or 13 || (b >= 32 && b < 127)) printable++;
        }

        return length > 0 && printable * 10 >= length * 9;
    }

    private static string HexDump(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 4);

        for (int offset = 0; offset < data.Length; offset += 16)
        {
            int run = Math.Min(16, data.Length - offset);
            sb.Append(offset.ToString("x8", System.Globalization.CultureInfo.InvariantCulture)).Append("  ");

            for (int i = 0; i < 16; i++)
            {
                sb.Append(i < run
                    ? data[offset + i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture)
                    : "  ").Append(' ');
                if (i == 7) sb.Append(' ');
            }

            sb.Append(' ');
            for (int i = 0; i < run; i++)
            {
                byte b = data[offset + i];
                sb.Append(b >= 32 && b < 127 ? (char)b : '.');
            }

            sb.Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>Parses a details string, or an empty element when it is not one.</summary>
    /// <remarks>
    /// Details are written by whichever collector emitted the event, and not every one of
    /// them writes JSON. A row with unreadable details is still a row worth showing.
    /// </remarks>
    private static JsonElement Facts(string? details)
    {
        if (string.IsNullOrEmpty(details)) return default;

        try
        {
            using JsonDocument document = JsonDocument.Parse(details);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return default;
        }
    }

    /// <summary>
    /// The header names and values out of a proxied exchange's details.
    /// </summary>
    /// <remarks>
    /// The body's hash and length share the same object and are not headers, so they are
    /// dropped here rather than rendered as though the server had sent them.
    /// </remarks>
    private static List<object> Headers(JsonElement facts)
    {
        var headers = new List<object>();
        if (facts.ValueKind != JsonValueKind.Object) return headers;

        foreach (JsonProperty property in facts.EnumerateObject())
        {
            if (property.Name is "body_sha256" or "body_bytes") continue;
            if (property.Value.ValueKind != JsonValueKind.String) continue;

            headers.Add(new { name = property.Name, value = property.Value.GetString() });
        }

        return headers;
    }

    private static string? Text(JsonElement o, string name)
        => o.ValueKind == JsonValueKind.Object
           && o.TryGetProperty(name, out JsonElement v)
           && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static long Number(JsonElement o, string name)
        => o.ValueKind == JsonValueKind.Object
           && o.TryGetProperty(name, out JsonElement v)
           && v.TryGetInt64(out long parsed)
            ? parsed
            : 0;

    private static bool Flag(JsonElement o, string name)
        => o.ValueKind == JsonValueKind.Object
           && o.TryGetProperty(name, out JsonElement v)
           && v.ValueKind == JsonValueKind.True;

    private static object Project(ScoredArtifact finding) => new
    {
        risk = finding.Risk.ToString(),
        score = finding.Score,
        category = finding.Observation.Category.ToString(),
        action = finding.Observation.Action.ToString(),
        target = finding.Observation.Target,
        target2 = finding.Observation.Target2,
        oldValue = finding.Observation.OldValue,
        newValue = finding.Observation.NewValue,
        reasons = finding.Reasons,
        seq = finding.Observation.Seq,
        when = finding.Observation.Timestamp,
        source = finding.Observation.Source.ToString(),
        confidence = finding.Observation.Confidence.ToString(),
    };

    /// <summary>
    /// Projects the network layer into four tables an analyst reads separately.
    /// </summary>
    /// <remarks>
    /// Separate rather than one merged timeline because the questions are different.
    /// "Which host did it talk to" is answered by connections; "what did it ask for" by
    /// requests; "what name did it look up" by DNS. Merging them produces a list where
    /// every row needs its own reading.
    /// </remarks>
    private static object BuildNetwork(
        SessionStore store,
        Dictionary<ProcessKey, ProcessNode> byKey,
        HashSet<ProcessKey> inScope,
        List<NetworkFlow> storedFlows,
        ExportRequest request)
    {
        string Name(ProcessKey key)
            => key == ProcessKey.None ? string.Empty
             : byKey.TryGetValue(key, out ProcessNode? node) ? node.ImageName
             : $"pid {key.Pid}";

        // The network tables answer "where did the subject connect". On a live desktop
        // the flow table also holds every other program's traffic — the browser, the
        // update service, the mail client — and listing it here made a session claim
        // the subject had contacted 84 hosts when it had contacted three. Rows have to
        // belong to the subject's process tree to appear.
        //
        // Rows nobody could attribute are counted rather than shown, because they might
        // be the subject's and might not, and silently dropping them would repeat the
        // same mistake in the other direction.
        int unattributed = 0;

        // Same reasoning as the finding filter: with no subject there is no "outside the
        // subject's tree", and applying the rule anyway empties the network view of a
        // system-wide capture entirely.
        bool scoped = inScope.Count > 0;

        bool Owned(ProcessKey actor)
        {
            if (!scoped || request.IncludeOutOfScope) return true;
            if (actor == ProcessKey.None) { unattributed++; return false; }
            return inScope.Contains(actor);
        }

        var requests = new List<object>();
        var dns = new List<object>();
        var tls = new List<object>();

        var wanted = new List<EventCategory>();
        if (request.Allows(EventCategory.Http)) wanted.Add(EventCategory.Http);
        if (request.Allows(EventCategory.Dns)) wanted.Add(EventCategory.Dns);
        if (request.Allows(EventCategory.Tls)) wanted.Add(EventCategory.Tls);

        if (wanted.Count > 0)
        {
            foreach (Observation o in store.Query(new ObservationQuery { Categories = wanted }))
            {
                if (!Owned(o.Actor)) continue;

                switch (o.Category)
                {
                    case EventCategory.Http when requests.Count < request.NetworkRowLimit:
                        bool isResponse = o.Action == EventAction.HttpResponse;

                        // The proxy writes the headers and the body's hash into the
                        // details as one flat object. Left as an opaque string, as it was,
                        // the view could show a size and nothing else — so a POST that
                        // uploaded 45 bytes was a row saying 45 bytes, with the bytes
                        // themselves sitting unreachable in the session the whole time.
                        JsonElement http = Facts(o.Details);
                        string? httpBody = Text(http, "body_sha256");

                        requests.Add(new
                        {
                            seq = o.Seq,
                            when = o.Timestamp,
                            process = Name(o.Actor),
                            pid = o.Actor.Pid,
                            direction = isResponse ? "response" : "request",
                            method = isResponse ? null : o.Target2,
                            status = isResponse ? o.Target2 : null,
                            url = o.Target,
                            bytes = o.Bytes,
                            causedBy = o.CausedBySeq,

                            // Whether a body is readable is a property of how it was
                            // observed: the proxy sees plaintext, the ETW stacks see a
                            // URL and a length. Saying which prevents "no body" from
                            // being read as "no data was sent".
                            source = o.Source.ToString(),
                            confidence = o.Confidence.ToString(),
                            details = o.Details,

                            // Headers as a list rather than the raw object, so the view can
                            // render them without knowing which keys are headers and which
                            // are the body's bookkeeping.
                            headers = Headers(http),
                            bodyHash = httpBody,
                            bodyBytes = Number(http, "body_bytes"),
                            bodyPreview = Preview(store, httpBody, request),
                        });
                        break;

                    case EventCategory.Dns when dns.Count < request.NetworkRowLimit:
                        dns.Add(new
                        {
                            seq = o.Seq,
                            when = o.Timestamp,
                            process = Name(o.Actor),
                            pid = o.Actor.Pid,
                            query = o.Target,
                            type = o.Action == EventAction.DnsResponse ? null : o.Target2,
                            answer = o.Action == EventAction.DnsResponse ? o.Target2 : null,
                            status = o.Status.ToString(),
                        });
                        break;

                    case EventCategory.Tls when tls.Count < request.NetworkRowLimit:
                        tls.Add(new
                        {
                            seq = o.Seq,
                            when = o.Timestamp,
                            process = Name(o.Actor),
                            pid = o.Actor.Pid,
                            serverName = o.Target,
                            protocol = o.Target2,
                            cipher = o.NewValue,
                        });
                        break;
                }
            }
        }

        // Who is on the other end of a conversation that never leaves this machine.
        //
        // Both ends of a loopback connection are recorded as separate flows — deliberately,
        // because the same bytes are seen twice and each end has its own owner. That also
        // means the other end can be looked up: the flow whose local endpoint is this
        // one's remote endpoint is the peer, and its owner is the process being talked to.
        //
        // Worth doing because the contents cannot be captured. The packet monitor watches
        // network adapters and loopback traffic crosses none, so "it connected to
        // 127.0.0.1:61274" was the whole of what a session could say — and naming the
        // program at the other end answers most of what the operator wanted to know.
        var byLocalEndpoint = new Dictionary<string, NetworkFlow>(StringComparer.OrdinalIgnoreCase);
        foreach (NetworkFlow flow in storedFlows)
            byLocalEndpoint.TryAdd($"{flow.Key.LocalAddress}:{flow.Key.LocalPort}", flow);

        string? PeerProcess(NetworkFlow flow)
        {
            if (!System.Net.IPAddress.IsLoopback(flow.Key.RemoteAddress)) return null;
            if (!byLocalEndpoint.TryGetValue($"{flow.Key.RemoteAddress}:{flow.Key.RemotePort}", out NetworkFlow? peer))
                return null;
            if (peer.Owner == ProcessKey.None || peer.Owner == flow.Owner) return Name(peer.Owner);

            return Name(peer.Owner);
        }

        List<object> flows = request.Allows(EventCategory.Network)
            ? storedFlows
                .Where(f => Owned(f.Owner))
                .OrderByDescending(static f => f.BytesSent + f.BytesReceived)
                .Take(request.NetworkRowLimit)
                .Select(f => (object)new
                {
                    peerProcess = PeerProcess(f),
                    onThisMachine = System.Net.IPAddress.IsLoopback(f.Key.RemoteAddress),
                    protocol = f.Key.Protocol.ToString(),
                    local = $"{f.Key.LocalAddress}:{f.Key.LocalPort}",
                    remote = $"{f.Key.RemoteAddress}:{f.Key.RemotePort}",

                    // A DNS answer that matched is preferred over an SNI: the name the
                    // program asked for is what it meant, and SNI can be absent or
                    // encrypted while the lookup still happened.
                    remoteHost = f.ResolvedHost ?? f.ServerName,
                    tls = f.TlsVersion,
                    alpn = f.Alpn,
                    process = Name(f.Owner),
                    pid = f.Owner.Pid,
                    sent = f.BytesSent,
                    received = f.BytesReceived,
                    firstSeen = f.FirstSeen,
                    lastSeen = f.LastSeen,
                    confidence = f.OwnerConfidence.ToString(),
                    evidence = f.OwnerEvidence,
                })
                .ToList()
            : new List<object>();

        return new
        {
            requests,
            flows,
            dns,
            tls,
            conversations = BuildConversations(store, byKey, Owned, request),

            // Both numbers exist so a shorter list is never read as a quieter program.
            unattributed,
            truncated = requests.Count >= request.NetworkRowLimit
                        || dns.Count >= request.NetworkRowLimit
                        || tls.Count >= request.NetworkRowLimit
                        || flows.Count >= request.NetworkRowLimit,
        };
    }
}
