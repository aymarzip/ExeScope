using System.Threading.Channels;
using Grpc.Core;
using ExeScope.Contracts.Grpc;
using ExeScope.Contracts.Security;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Mapping;
using ExeScope.Engine.Session;

namespace ExeScope.Agent.Windows.Services;

public class AgentTelemetryServiceImpl : AgentTelemetryService.AgentTelemetryServiceBase
{
    private readonly AnalysisSessionManager _sessionManager;
    private readonly IDiagnosticLogger _logger;
    private readonly string _expectedAuthToken;

    public AgentTelemetryServiceImpl(
        AnalysisSessionManager sessionManager,
        IDiagnosticLogger logger,
        string expectedAuthToken)
    {
        _sessionManager = sessionManager;
        _logger = logger;
        _expectedAuthToken = expectedAuthToken;
    }

    private void ValidateAuth(string? candidateToken, ServerCallContext context)
    {
        string? headerToken = context.RequestHeaders.GetValue(IpcAuthToken.HeaderName);
        string? tokenToCheck = !string.IsNullOrEmpty(candidateToken) ? candidateToken : headerToken;

        if (!IpcAuthToken.ValidateToken(tokenToCheck, _expectedAuthToken))
        {
            _logger.Warn("AgentService", $"Unauthorized gRPC request rejected from {context.Peer}");
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid or missing ExeScope IPC authorization token."));
        }
    }

    public override Task<AgentStatusResponse> GetStatus(AgentStatusRequest request, ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        var resp = new AgentStatusResponse
        {
            IsReady = true,
            IsElevated = _sessionManager.IsElevated,
            CurrentState = _sessionManager.State.ToString(),
            SessionId = _sessionManager.CurrentMetadata?.SessionId ?? string.Empty,
            TotalEventsRecorded = _sessionManager.TotalEventsRecorded,
            TotalEventsDropped = _sessionManager.TotalEventsDropped,
            SessionSizeBytes = _sessionManager.SessionSizeBytes,
            TargetExePath = _sessionManager.TargetExe?.OriginalPath ?? string.Empty,
            RootPid = _sessionManager.CurrentMetadata?.RootProcessId ?? 0
        };

        return Task.FromResult(resp);
    }

    public override async Task<StartSessionResponse> StartSession(StartSessionRequest request, ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        try
        {
            if (string.IsNullOrWhiteSpace(request.TargetExePath) || !File.Exists(request.TargetExePath))
            {
                return new StartSessionResponse
                {
                    Success = false,
                    Message = $"Target executable file does not exist: {request.TargetExePath}"
                };
            }

            _sessionManager.SetTargetExe(request.TargetExePath);

            var config = new SessionConfig
            {
                OutputDirectory = string.IsNullOrWhiteSpace(request.OutputDirectory)
                    ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "ExeScope_Results")
                    : request.OutputDirectory,
                EnableArtifactSaving = request.EnableArtifacts,
                MaxArtifactFileSizeBytes = request.MaxArtifactSizeMb > 0 ? request.MaxArtifactSizeMb * 1024L * 1024L : 10 * 1024L * 1024L,
                MaxTotalArtifactStorageBytes = request.MaxStorageSizeMb > 0 ? request.MaxStorageSizeMb * 1024L * 1024L : 100 * 1024L * 1024L,
                EnablePacketCapture = request.EnablePacketCapture,
                EnableInjectionTracking = request.EnableInjectionTracking,
                TrackInjectionTargetEvents = request.TrackInjectionTargetEvents
            };

            _sessionManager.UpdateConfig(config);
            await _sessionManager.StartWaitingAsync().ConfigureAwait(false);

            return new StartSessionResponse
            {
                Success = true,
                Message = "Session initialized. Awaiting process launch.",
                SessionId = _sessionManager.CurrentMetadata?.SessionId ?? string.Empty,
                TargetSha256 = _sessionManager.TargetExe?.Sha256 ?? string.Empty,
                SignatureStatus = _sessionManager.TargetExe?.SignatureStatus ?? "Unknown"
            };
        }
        catch (Exception ex)
        {
            _logger.Error("AgentService", "Failed to start session", ex);
            return new StartSessionResponse
            {
                Success = false,
                Message = ex.Message
            };
        }
    }

    public override async Task<StopSessionResponse> StopSession(StopSessionRequest request, ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        try
        {
            await _sessionManager.StopRecordingAsync(request.Reason ?? "Stop requested via gRPC").ConfigureAwait(false);

            string reportPath = Path.Combine(_sessionManager.CurrentSessionDirectory ?? "", "report.html");

            return new StopSessionResponse
            {
                Success = true,
                Message = "Session successfully stopped and report finalized.",
                ReportPath = reportPath,
                TotalEvents = _sessionManager.TotalEventsRecorded,
                TotalArtifacts = _sessionManager.CurrentMetadata?.TotalArtifactsSaved ?? 0
            };
        }
        catch (Exception ex)
        {
            _logger.Error("AgentService", "Failed to stop session", ex);
            return new StopSessionResponse
            {
                Success = false,
                Message = ex.Message
            };
        }
    }

    public override async Task StreamEvents(
        StreamEventsRequest request,
        IServerStreamWriter<TelemetryEnvelope> responseStream,
        ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        var channel = Channel.CreateBounded<TelemetryEnvelope>(new BoundedChannelOptions(20_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        });

        void OnEventRecorded(AnalysisEvent evt)
        {
            try
            {
                var envelope = DomainContractMapper.ToGrpcEnvelope(evt);
                channel.Writer.TryWrite(envelope);
            }
            catch
            {
                // Ignore channel write errors if disposing
            }
        }

        _sessionManager.EventRecorded += OnEventRecorded;

        try
        {
            while (!context.CancellationToken.IsCancellationRequested)
            {
                var envelope = await channel.Reader.ReadAsync(context.CancellationToken).ConfigureAwait(false);
                await responseStream.WriteAsync(envelope, context.CancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on client disconnection
        }
        finally
        {
            _sessionManager.EventRecorded -= OnEventRecorded;
            channel.Writer.TryComplete();
        }
    }

    public override async Task StreamArtifacts(
        StreamArtifactsRequest request,
        IServerStreamWriter<ArtifactMessage> responseStream,
        ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        var channel = Channel.CreateBounded<ArtifactMessage>(new BoundedChannelOptions(5_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        });

        void OnArtifactSaved(ArtifactRecord art)
        {
            try
            {
                var msg = new ArtifactMessage
                {
                    ProcessId = art.OriginatingProcessId,
                    OriginalPath = art.OriginalPath,
                    ArtifactFileName = art.ArtifactFileName,
                    Sha256 = art.Sha256,
                    SizeBytes = art.SizeBytes,
                    CopyStatus = art.CopyStatus.ToString(),
                    TimestampUtc = art.TimestampUtc.ToString("o")
                };
                channel.Writer.TryWrite(msg);
            }
            catch
            {
                // Ignore
            }
        }

        _sessionManager.ArtifactSaved += OnArtifactSaved;

        try
        {
            while (!context.CancellationToken.IsCancellationRequested)
            {
                var msg = await channel.Reader.ReadAsync(context.CancellationToken).ConfigureAwait(false);
                await responseStream.WriteAsync(msg, context.CancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
        finally
        {
            _sessionManager.ArtifactSaved -= OnArtifactSaved;
            channel.Writer.TryComplete();
        }
    }

    public override async Task<ExportReportResponse> ExportReport(ExportReportRequest request, ServerCallContext context)
    {
        ValidateAuth(request.AuthToken, context);

        try
        {
            await _sessionManager.GenerateReportAsync().ConfigureAwait(false);

            string defaultPath = Path.Combine(_sessionManager.CurrentSessionDirectory ?? "", "report.html");
            string targetPath = string.IsNullOrWhiteSpace(request.DestinationPath) ? defaultPath : request.DestinationPath;

            if (File.Exists(defaultPath) && !string.Equals(defaultPath, targetPath, StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(defaultPath, targetPath, overwrite: true);
            }

            string content = File.Exists(targetPath) ? await File.ReadAllTextAsync(targetPath).ConfigureAwait(false) : string.Empty;

            return new ExportReportResponse
            {
                Success = true,
                ReportPath = targetPath,
                HtmlContent = content
            };
        }
        catch (Exception ex)
        {
            _logger.Error("AgentService", "Failed to export report", ex);
            return new ExportReportResponse
            {
                Success = false,
                ErrorMessage = ex.Message
            };
        }
    }
}
