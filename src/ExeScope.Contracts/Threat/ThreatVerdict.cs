namespace ExeScope.Contracts.Threat;

public enum ThreatLevel
{
    Clean,
    Suspicious,
    Malicious
}

public enum IocSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public sealed record IndicatorOfCompromise(
    string RuleId,
    string Title,
    string Description,
    IocSeverity Severity,
    string? MitreTechniqueId = null,
    string? Evidence = null
);

public sealed record ThreatVerdictSummary
{
    public int Score { get; init; }
    public ThreatLevel Level { get; init; }
    public string SummaryText { get; init; } = string.Empty;
    public IReadOnlyList<IndicatorOfCompromise> Indicators { get; init; } = Array.Empty<IndicatorOfCompromise>();

    public string LevelDisplay => Level switch
    {
        ThreatLevel.Clean => "Clean",
        ThreatLevel.Suspicious => "Suspicious",
        ThreatLevel.Malicious => "Malicious",
        _ => "Unknown"
    };

    public string HexColor => Level switch
    {
        ThreatLevel.Clean => "#8c9ba5",
        ThreatLevel.Suspicious => "#fa8c16",
        ThreatLevel.Malicious => "#f5222d",
        _ => "#8c9ba5"
    };
}
