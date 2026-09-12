using ExeScope.Core.Models;

namespace ExeScope.Engine.Collectors;

public interface IEventCollector : IAsyncDisposable
{
    string Name { get; }

    bool IsSupported { get; }

    string StatusDescription { get; }

    Task StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync();

    event Action<AnalysisEvent>? EventEmitted;
}

public class CollectorCapabilities
{
    public bool HasKernelEtwPrivileges { get; set; }

    public bool CanCollectProcesses { get; set; } = true;

    public bool CanCollectFileOperations { get; set; }

    public bool CanCollectRegistryOperations { get; set; }

    public bool CanCollectNetworkConnections { get; set; }

    public bool CanCollectDns { get; set; }

    public bool CanCapturePackets { get; set; }

    public List<string> ActiveSources { get; set; } = new();

    public List<string> Limitations { get; set; } = new();
}
