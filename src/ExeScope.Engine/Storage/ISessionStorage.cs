using ExeScope.Core.Models;

namespace ExeScope.Engine.Storage;

public interface ISessionStorage : IAsyncDisposable
{
    string SessionDirectory { get; }

    void EnqueueEvent(AnalysisEvent evt);

    Task FlushAsync();

    void SaveSessionMetadata(SessionMetadata metadata);

    void SaveProcessTree(ProcessNode? rootNode);

    long TotalEventsWritten { get; }

    long TotalEventsDropped { get; }

    long CalculateSessionSizeBytes();
}
