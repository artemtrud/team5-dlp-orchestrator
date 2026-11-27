using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://localhost:8000");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IncidentCorrelator>();
builder.Services.AddHostedService<RedisDnsSubscriber>();

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();

app.MapPost("/api/policy-events", (PolicyDecisionEvent policyEvent, IncidentCorrelator correlator) =>
{
    if (string.Equals(policyEvent.Decision, "allow", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Ok(new { status = "IGNORED", message = "Решение allow не создаёт инцидент" });
    }

    var incident = correlator.ProcessPolicyEvent(policyEvent);

    if (incident != null)
        return Results.Ok(new { status = "INCIDENT_CREATED", incident });

    return Results.Ok(new { status = "BUFFERED", message = "Событие policy_decision в буфере. Ждём dns_hit в окне 5 мин." });
})
.WithName("ReceivePolicyDecision")
.WithSummary("Приём события policy_decision (block / warn)");

app.MapPost("/api/dns-events", (DnsHitEvent dnsEvent, IncidentCorrelator correlator) =>
{
    var incident = correlator.ProcessDnsEvent(dnsEvent);

    if (incident != null)
        return Results.Ok(new { status = "INCIDENT_CREATED", incident });

    return Results.Ok(new { status = "BUFFERED", message = "Событие dns_hit в буфере. Ждём policy_decision в окне 5 мин." });
})
.WithName("ReceiveDnsEvent")
.WithSummary("Тестовый приём события dns_hit");

app.MapGet("/api/policies", () =>
{
    var policies = new[]
    {
        new { entity = "PASSPORT", action = "block", min_confidence = 0.90 },
        new { entity = "BANK_CARD", action = "block", min_confidence = 0.90 },
        new { entity = "SECRET", action = "block", min_confidence = 0.75 },
        new { entity = "PHONE", action = "warn", min_confidence = 0.80 }
    };
    return Results.Ok(policies);
})
.WithName("GetPolicies")
.WithSummary("Получить список политик реагирования");

app.MapGet("/api/incidents", (IncidentCorrelator correlator) =>
    Results.Ok(correlator.GetAllIncidents()))
.WithName("GetIncidents")
.WithSummary("Получить список всех инцидентов");

app.Run();



public record DnsHitEvent(
    [property: JsonPropertyName("client_ip")] string Ip,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("ts")] double Timestamp
);

public record DetectedEntity(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("start")] int Start,
    [property: JsonPropertyName("end")] int End,
    [property: JsonPropertyName("confidence")] double Confidence
);

public record PolicyDecisionEvent(
    [property: JsonPropertyName("client_ip")] string Ip,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("masked_text")] string MaskedText,
    [property: JsonPropertyName("ts")] double Timestamp,
    [property: JsonPropertyName("entities")] List<DetectedEntity>? Entities
);

public record Incident(
    Guid Id,
    string MaskedIp,
    string Domain,
    string Decision,
    string Severity,
    string MaskedText,
    List<DetectedEntity> Entities,
    long CreatedAt,
    string Status
);


public class IncidentCorrelator
{
    private readonly ConcurrentDictionary<string, DnsHitEvent> _dnsBuffer = new();
    private readonly ConcurrentDictionary<string, PolicyDecisionEvent> _policyBuffer = new();
    private readonly List<Incident> _incidents = new();
    private const double WindowSeconds = 300.0; // 5 минут

    public Incident? ProcessDnsEvent(DnsHitEvent dns)
    {
        string key = $"{dns.Ip}_{dns.Domain}";

        if (_policyBuffer.TryRemove(key, out var policy) && Math.Abs(dns.Timestamp - policy.Timestamp) <= WindowSeconds)
        {
            return CreateIncident(dns.Ip, dns.Domain, policy, (long)Math.Max(dns.Timestamp, policy.Timestamp));
        }

        _dnsBuffer[key] = dns;
        return null;
    }

    public Incident? ProcessPolicyEvent(PolicyDecisionEvent policy)
    {
        string key = $"{policy.Ip}_{policy.Domain}";

        if (_dnsBuffer.TryRemove(key, out var dns) && Math.Abs(policy.Timestamp - dns.Timestamp) <= WindowSeconds)
        {
            return CreateIncident(policy.Ip, policy.Domain, policy, (long)Math.Max(dns.Timestamp, policy.Timestamp));
        }

        _policyBuffer[key] = policy;
        return null;
    }

    private Incident CreateIncident(string ip, string domain, PolicyDecisionEvent policy, long timestamp)
    {
        string severity = string.Equals(policy.Decision, "block", StringComparison.OrdinalIgnoreCase)
            ? "high"
            : "medium";

        var incident = new Incident(
            Id: Guid.NewGuid(),
            MaskedIp: MaskIp(ip),
            Domain: domain,
            Decision: policy.Decision.ToLower(),
            Severity: severity,
            MaskedText: policy.MaskedText,
            Entities: policy.Entities ?? new List<DetectedEntity>(),
            CreatedAt: timestamp,
            Status: "new"
        );

        _incidents.Add(incident);
        Console.WriteLine($"[ИНЦИДЕНТ] {incident.Id} | IP: {incident.MaskedIp} | Severity: {severity} | Сущностей: {incident.Entities.Count}");
        return incident;
    }

    private string MaskIp(string ip)
    {
        var parts = ip.Split('.');
        return parts.Length == 4 ? $"{parts}.{parts}.***.***" : "masked_ip";
    }

    public IEnumerable<Incident> GetAllIncidents() => _incidents;
}

public class RedisDnsSubscriber : BackgroundService
{
    private readonly IncidentCorrelator _correlator;

    public RedisDnsSubscriber(IncidentCorrelator correlator) => _correlator = correlator;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var redisHost = Environment.GetEnvironmentVariable("REDIS_HOST") ?? "195.133.49.158:6379";
            var redis = await ConnectionMultiplexer.ConnectAsync($"{redisHost},abortConnect=false");
            var db = redis.GetDatabase();

            Console.WriteLine($"[REDIS STREAMS] Подключено к {redisHost}, слушаем поток dns_hit...");

            RedisValue lastId = "0-0";

            while (!stoppingToken.IsCancellationRequested)
            {
                var entries = await db.StreamReadAsync("dns_hit", lastId, count: 10);

                if (entries.Length > 0)
                {
                    foreach (var entry in entries)
                    {
                        lastId = entry.Id;

                        var rawJson = entry.Values.FirstOrDefault(v => v.Name == "data" || v.Name == "payload").Value;
                        DnsHitEvent? dnsEvent = null;

                        if (!rawJson.IsNullOrEmpty)
                        {
                            dnsEvent = JsonSerializer.Deserialize<DnsHitEvent>(rawJson.ToString());
                        }
                        else
                        {
                            var dict = entry.Values.ToDictionary(v => v.Name.ToString(), v => v.Value.ToString());
                            if (dict.TryGetValue("client_ip", out var ip) && dict.TryGetValue("domain", out var domain))
                            {
                                double.TryParse(dict.GetValueOrDefault("ts", "0"), NumberStyles.Any, CultureInfo.InvariantCulture, out var ts);
                                dnsEvent = new DnsHitEvent(ip, domain, ts);
                            }
                        }

                        if (dnsEvent != null)
                        {
                            Console.WriteLine($"[REDIS STREAM] Получен dns_hit: {dnsEvent.Ip} -> {dnsEvent.Domain} (ts: {dnsEvent.Timestamp})");
                            _correlator.ProcessDnsEvent(dnsEvent);
                        }
                    }
                }
                else
                {
                    await Task.Delay(300, stoppingToken);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[INFO] Ошибка подключения к Redis ({ex.Message}). Для теста используйте POST /api/dns-events.");
        }
    }
}
