namespace ExeScope.Core.Models;

public enum AnalysisSessionState
{
    Ready,
    WaitingForLaunch,
    Recording,
    Completed,
    Error
}
