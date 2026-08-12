using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CaYaTrace.Analysis.Ai;

public sealed record OllamaModel(string Name, string ParameterSize, string Quantization, long SizeBytes,
    IReadOnlyList<string> Capabilities)
{
    public bool IsThinkingModel => Capabilities.Contains("thinking", StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Rough parameter count in billions, parsed from Ollama's label. Used only to
    /// order candidates and to warn about very small models.
    /// </summary>
    public double Billions
    {
        get
        {
            string raw = ParameterSize.Trim();
            if (raw.EndsWith("B", StringComparison.OrdinalIgnoreCase)
                && double.TryParse(raw[..^1], System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double b))
                return b;

            if (raw.EndsWith("M", StringComparison.OrdinalIgnoreCase)
                && double.TryParse(raw[..^1], System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double m))
                return m / 1000.0;

            return 0;
        }
    }
}

public sealed class OllamaException : Exception
{
    public OllamaException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Talks to a local Ollama instance.
/// </summary>
/// <remarks>
/// <para>
/// Two settings here are not tuning knobs, they are the difference between the feature
/// working and appearing broken. Both were established by measurement against the
/// models actually installed on a developer machine, not from documentation.
/// </para>
/// <para>
/// <b>Structured output is mandatory.</b> Asked in free form, a 0.5B model invented its own
/// JSON shape, a 1B model invented a different one, and a 0.8B model returned nothing —
/// none answered the question. Given a JSON schema, the same 1B model classified an
/// autostart registry write correctly on the first attempt. Constraining the shape also
/// made it roughly seventy times faster, because generation stops when the object
/// closes instead of rambling to the token limit.
/// </para>
/// <para>
/// <b>Thinking must be switched off.</b> Reasoning models put their answer in a separate
/// <c>thinking</c> field and leave <c>response</c> empty, which looks exactly like a broken
/// integration. Disabling it also cut one model's latency from 34.7s to 1.3s for an
/// identical answer. Chain-of-thought earns nothing here: every task this pipeline
/// issues is a single classification against a fixed label set.
/// </para>
/// </remarks>
public sealed class OllamaClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    public Uri Endpoint { get; }

    public OllamaClient(Uri? endpoint = null, HttpClient? http = null)
    {
        Endpoint = endpoint ?? new Uri("http://localhost:11434");
        _ownsClient = http is null;
        _http = http ?? new HttpClient();

        // A cold model load can take a while; a per-request timeout is applied on top
        // of this by the caller's cancellation token.
        if (_ownsClient) _http.Timeout = TimeSpan.FromMinutes(10);
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            using HttpResponseMessage response =
                await _http.GetAsync(new Uri(Endpoint, "/api/version"), cts.Token).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<OllamaModel>> ListModelsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using HttpResponseMessage response =
                await _http.GetAsync(new Uri(Endpoint, "/api/tags"), cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            using JsonDocument doc = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));

            if (!doc.RootElement.TryGetProperty("models", out JsonElement models))
                return Array.Empty<OllamaModel>();

            var result = new List<OllamaModel>();
            foreach (JsonElement model in models.EnumerateArray())
            {
                string name = model.TryGetProperty("name", out JsonElement n) ? n.GetString() ?? "" : "";
                if (name.Length == 0) continue;

                string size = "", quant = "";
                if (model.TryGetProperty("details", out JsonElement details))
                {
                    size = details.TryGetProperty("parameter_size", out JsonElement ps) ? ps.GetString() ?? "" : "";
                    quant = details.TryGetProperty("quantization_level", out JsonElement q) ? q.GetString() ?? "" : "";
                }

                var caps = new List<string>();
                if (model.TryGetProperty("capabilities", out JsonElement capsElement)
                    && capsElement.ValueKind == JsonValueKind.Array)
                {
                    caps.AddRange(capsElement.EnumerateArray()
                        .Select(static c => c.GetString() ?? string.Empty)
                        .Where(static c => c.Length > 0));
                }

                long bytes = model.TryGetProperty("size", out JsonElement s) ? s.GetInt64() : 0;
                result.Add(new OllamaModel(name, size, quant, bytes, caps));
            }

            return result;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new OllamaException($"could not list models at {Endpoint}", ex);
        }
    }

    /// <summary>
    /// Runs one prompt and returns the raw response text, shaped by <paramref name="schema"/>.
    /// </summary>
    /// <param name="schema">
    /// JSON schema the answer must conform to. Never null in this pipeline: unconstrained
    /// generation from a small model does not produce usable output.
    /// </param>
    /// <summary>
    /// Asks for prose rather than a structured answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An explicit overload, and not an optional argument on the one below, because that
    /// one takes <c>object schema</c> in third position — so <c>GenerateAsync(model, prompt,
    /// token)</c> compiled happily, boxed the cancellation token into the response-format
    /// field, and passed <c>default</c> as the real token. The request then carried a
    /// nonsense format constraint and could not be cancelled, so the assistant sat on
    /// "working" forever and its timeout never fired. Measured, from a chat that never
    /// answered.
    /// </para>
    /// <para>
    /// Slightly warmer than the structured path and allowed more tokens, because this is
    /// used to reword an answer that is already correct: determinism buys nothing here,
    /// and a sentence cut off mid-clause is worse than a slightly different sentence.
    /// </para>
    /// </remarks>
    public Task<string> GenerateAsync(string model, string prompt, CancellationToken cancellationToken)
        => GenerateAsync(model, prompt, schema: null, maxTokens: 800, temperature: 0.2,
            seed: null, cancellationToken);

    public async Task<string> GenerateAsync(
        string model,
        string prompt,
        object? schema,
        int maxTokens = 512,
        double temperature = 0,
        int? seed = null,
        CancellationToken cancellationToken = default)
    {
        var request = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["prompt"] = prompt,
            ["stream"] = false,

            // Reasoning models otherwise return their answer in `thinking` and leave
            // `response` empty. See the class remarks.
            ["think"] = false,

            ["options"] = new Dictionary<string, object?>
            {
                // Deterministic by default. An analyst re-running the same session must
                // get the same findings, or the output cannot be cited.
                ["temperature"] = temperature,
                ["num_predict"] = maxTokens,
                ["seed"] = seed ?? 42,
                ["top_p"] = temperature <= 0 ? 1.0 : 0.9,
            },
        };

        // Omitted entirely when there is no schema. Sending a null format makes some
        // builds refuse the request rather than treating it as unconstrained.
        if (schema is not null) request["format"] = schema;

        try
        {
            using HttpResponseMessage response = await _http
                .PostAsJsonAsync(new Uri(Endpoint, "/api/generate"), request, cancellationToken)
                .ConfigureAwait(false);

            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                throw new OllamaException($"ollama returned {(int)response.StatusCode}: {Truncate(body)}");

            using JsonDocument doc = JsonDocument.Parse(body);

            if (doc.RootElement.TryGetProperty("error", out JsonElement error))
                throw new OllamaException($"ollama error: {error.GetString()}");

            string text = doc.RootElement.TryGetProperty("response", out JsonElement r)
                ? r.GetString() ?? string.Empty
                : string.Empty;

            // Defence in depth: if a build ignores `think:false`, the answer may still
            // be in `thinking`. Better to recover it than to report an empty result.
            if (text.Trim().Length == 0
                && doc.RootElement.TryGetProperty("thinking", out JsonElement thinking))
            {
                text = thinking.GetString() ?? string.Empty;
            }

            return text.Trim();
        }
        catch (OllamaException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new OllamaException($"request to {Endpoint} failed", ex);
        }
    }

    /// <summary>
    /// Runs a prompt and deserializes the answer, returning null when the model
    /// produced something unusable.
    /// </summary>
    /// <remarks>
    /// Returning null rather than throwing is deliberate. A weak model failing one item
    /// out of forty is normal operation, not an error condition; the pipeline drops
    /// that item and carries on rather than abandoning the analysis.
    /// </remarks>
    public async Task<T?> GenerateAsync<T>(
        string model,
        string prompt,
        object schema,
        int maxTokens = 512,
        double temperature = 0,
        int? seed = null,
        CancellationToken cancellationToken = default) where T : class
    {
        string text = await GenerateAsync(model, prompt, schema, maxTokens, temperature, seed, cancellationToken)
            .ConfigureAwait(false);

        if (text.Length == 0) return null;

        try
        {
            return JsonSerializer.Deserialize<T>(text, JsonOptions);
        }
        catch (JsonException)
        {
            // Some models wrap the object in prose or a code fence despite the schema.
            string? salvaged = ExtractFirstJsonObject(text);
            if (salvaged is null) return null;

            try { return JsonSerializer.Deserialize<T>(salvaged, JsonOptions); }
            catch (JsonException) { return null; }
        }
    }

    /// <summary>Finds the first balanced JSON object in a string.</summary>
    internal static string? ExtractFirstJsonObject(string text)
    {
        int start = text.IndexOf('{');
        if (start < 0) return null;

        int depth = 0;
        bool inString = false, escaped = false;

        for (int i = start; i < text.Length; i++)
        {
            char c = text[i];

            if (escaped) { escaped = false; continue; }
            if (c == '\\' && inString) { escaped = true; continue; }
            if (c == '"') { inString = !inString; continue; }
            if (inString) continue;

            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return text[start..(i + 1)];
        }

        return null;
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    private static string Truncate(string value) => value.Length <= 300 ? value : value[..300] + "…";

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}
