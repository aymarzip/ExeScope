using System.IO.Pipes;
using System.Net.Http;
using Grpc.Core;
using Grpc.Net.Client;
using ExeScope.Contracts.Grpc;
using ExeScope.Contracts.Security;

namespace ExeScope.GUI.Services;

public class AgentClientService : IAsyncDisposable
{
    private GrpcChannel? _channel;
    private AgentTelemetryService.AgentTelemetryServiceClient? _client;
    private string _authToken = string.Empty;
    private bool _isConnected;
    private CancellationTokenSource? _streamingCts;

    public bool IsConnected => _isConnected;
    public string AuthToken => _authToken;

    public event Action<bool, string>? ConnectionStateChanged;
    public event Action<TelemetryEnvelope>? EventReceived;
    public event Action<ArtifactMessage>? ArtifactReceived;

    public async Task<bool> ConnectAsync(string addressOrPipe, string? authToken = null)
    {
        try
        {
            _authToken = !string.IsNullOrWhiteSpace(authToken) ? authToken : IpcAuthToken.LoadOrCreateToken();

            await DisconnectAsync();

            if (OperatingSystem.IsWindows() && addressOrPipe.Contains("pipe", StringComparison.OrdinalIgnoreCase))
            {
                string pipeName = addressOrPipe.Contains('\\') ? Path.GetFileName(addressOrPipe) : addressOrPipe;
                var handler = new SocketsHttpHandler
                {
                    ConnectCallback = async (context, token) =>
                    {
                        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                        await pipe.ConnectAsync(token).ConfigureAwait(false);
                        return pipe;
                    }
                };

                _channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
                {
                    HttpHandler = handler,
                    MaxReceiveMessageSize = 32 * 1024 * 1024
                });
            }
            else
            {
                string endpoint = addressOrPipe.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? addressOrPipe
                    : $"http://{addressOrPipe}";

                _channel = GrpcChannel.ForAddress(endpoint, new GrpcChannelOptions
                {
                    MaxReceiveMessageSize = 32 * 1024 * 1024
                });
            }

            _client = new AgentTelemetryService.AgentTelemetryServiceClient(_channel);

            var headers = CreateAuthHeaders();
            var status = await _client.GetStatusAsync(new AgentStatusRequest { AuthToken = _authToken }, headers)
                .ResponseAsync.WaitAsync(TimeSpan.FromSeconds(3));

            _isConnected = true;
            ConnectionStateChanged?.Invoke(true, $"Connected (State: {status.CurrentState}, Elevated: {status.IsElevated})");

            StartBackgroundStreaming();
            return true;
        }
        catch (Exception ex)
        {
            _isConnected = false;
            ConnectionStateChanged?.Invoke(false, $"Connection failed: {ex.Message}");
            return false;
        }
    }

    public async Task DisconnectAsync()
    {
        _streamingCts?.Cancel();
        _streamingCts = null;

        _isConnected = false;
        if (_channel != null)
        {
            await _channel.ShutdownAsync();
            _channel.Dispose();
            _channel = null;
        }
        _client = null;
        ConnectionStateChanged?.Invoke(false, "Disconnected");
    }

    private Metadata CreateAuthHeaders()
    {
        return new Metadata
        {
            { IpcAuthToken.HeaderName, _authToken }
        };
    }

    public async Task<AgentStatusResponse?> GetStatusAsync()
    {
        if (_client == null) return null;
        try
        {
            return await _client.GetStatusAsync(new AgentStatusRequest { AuthToken = _authToken }, CreateAuthHeaders());
        }
        catch
        {
            return null;
        }
    }

    public async Task<StartSessionResponse> StartSessionAsync(
        string targetExePath,
        string outputDir,
        bool enableArtifacts = true,
        int maxArtifactSizeMb = 10,
        int maxStorageMb = 100,
        bool enablePacketCapture = false,
        bool enableInjectionTracking = true,
        bool trackInjectionTargets = true)
    {
        if (_client == null)
            throw new InvalidOperationException("Not connected to ExeScope Agent.");

        var req = new StartSessionRequest
        {
            AuthToken = _authToken,
            TargetExePath = targetExePath,
            OutputDirectory = outputDir,
            EnableArtifacts = enableArtifacts,
            MaxArtifactSizeMb = maxArtifactSizeMb,
            MaxStorageSizeMb = maxStorageMb,
            EnablePacketCapture = enablePacketCapture,
            EnableInjectionTracking = enableInjectionTracking,
            TrackInjectionTargetEvents = trackInjectionTargets
        };

        return await _client.StartSessionAsync(req, CreateAuthHeaders());
    }

    public async Task<StopSessionResponse> StopSessionAsync(string reason = "Stopped by user")
    {
        if (_client == null)
            throw new InvalidOperationException("Not connected to ExeScope Agent.");

        var req = new StopSessionRequest
        {
            AuthToken = _authToken,
            Reason = reason
        };

        return await _client.StopSessionAsync(req, CreateAuthHeaders());
    }

    public async Task<ExportReportResponse> ExportReportAsync(string destinationPath)
    {
        if (_client == null)
            throw new InvalidOperationException("Not connected to ExeScope Agent.");

        var req = new ExportReportRequest
        {
            AuthToken = _authToken,
            DestinationPath = destinationPath
        };

        return await _client.ExportReportAsync(req, CreateAuthHeaders());
    }

    private void StartBackgroundStreaming()
    {
        _streamingCts?.Cancel();
        _streamingCts = new CancellationTokenSource();
        var ct = _streamingCts.Token;

        Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested && _client != null)
            {
                try
                {
                    using var call = _client.StreamEvents(new StreamEventsRequest { AuthToken = _authToken }, CreateAuthHeaders(), cancellationToken: ct);
                    if (!_isConnected)
                    {
                        _isConnected = true;
                        ConnectionStateChanged?.Invoke(true, "Connected (Telemetry stream active)");
                    }

                    while (await call.ResponseStream.MoveNext(ct).ConfigureAwait(false))
                    {
                        var env = call.ResponseStream.Current;
                        EventReceived?.Invoke(env);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (_isConnected)
                    {
                        _isConnected = false;
                        ConnectionStateChanged?.Invoke(false, $"Connection lost: {ex.Message}");
                    }
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
            }
        }, ct);

        Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested && _client != null)
            {
                try
                {
                    using var call = _client.StreamArtifacts(new StreamArtifactsRequest { AuthToken = _authToken }, CreateAuthHeaders(), cancellationToken: ct);
                    while (await call.ResponseStream.MoveNext(ct).ConfigureAwait(false))
                    {
                        var art = call.ResponseStream.Current;
                        ArtifactReceived?.Invoke(art);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (_isConnected)
                    {
                        _isConnected = false;
                        ConnectionStateChanged?.Invoke(false, $"Artifact stream error: {ex.Message}");
                    }
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
            }
        }, ct);
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
    }
}
