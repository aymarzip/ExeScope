using ExeScope.Agent.Windows.Services;
using ExeScope.Contracts.Security;
using ExeScope.Core.Diagnostics;
using ExeScope.Engine.Session;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ExeScope.Agent.Windows;

public class Program
{
    public static async Task Main(string[] args)
    {
        Console.Title = "ExeScope Telemetry Agent (Windows)";
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("==========================================================");
        Console.WriteLine("   ExeScope Low-Level Windows Telemetry Agent (.NET 8)   ");
        Console.WriteLine("==========================================================");
        Console.ResetColor();

        string authToken = IpcAuthToken.LoadOrCreateToken();
        Console.WriteLine($"[SECURITY] IPC Auth Token: {authToken[..8]}...{authToken[^4..]}");
        Console.WriteLine($"[SECURITY] Token stored at: {IpcAuthToken.GetDefaultTokenPath()}");

        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();

        int port = IpcAuthToken.DefaultTcpPort;
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenLocalhost(port, o =>
            {
                o.Protocols = HttpProtocols.Http2;
            });

            // Also support Named Pipe on Windows
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    options.ListenNamedPipe(IpcAuthToken.DefaultNamedPipe, o =>
                    {
                        o.Protocols = HttpProtocols.Http2;
                    });
                    Console.WriteLine($"[IPC] Listening on Named Pipe: \\\\.\\pipe\\{IpcAuthToken.DefaultNamedPipe}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[IPC] Named Pipe registration note: {ex.Message}");
                }
            }
        });

        // Register core services
        var diagnosticLogger = new DiagnosticLogger();
        builder.Services.AddSingleton<IDiagnosticLogger>(diagnosticLogger);

        var sessionManager = new AnalysisSessionManager(diagnosticLogger);
        builder.Services.AddSingleton(sessionManager);

        builder.Services.AddSingleton(new AgentTelemetryServiceImpl(sessionManager, diagnosticLogger, authToken));
        builder.Services.AddGrpc(options =>
        {
            options.MaxReceiveMessageSize = 32 * 1024 * 1024;
            options.MaxSendMessageSize = 32 * 1024 * 1024;
        });

        var app = builder.Build();

        app.MapGrpcService<AgentTelemetryServiceImpl>();
        app.MapGet("/", () => "ExeScope Telemetry Agent is running. Connect via gRPC.");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[AGENT] Ready. Listening on http://localhost:{port} (gRPC HTTP/2)");
        Console.WriteLine($"[AGENT] Elevated: {sessionManager.IsElevated}");
        Console.ResetColor();

        await app.RunAsync();
    }
}
