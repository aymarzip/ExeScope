using System.Security.Principal;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Detection;
using ExeScope.Engine.Tracking;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace ExeScope.Engine.Collectors;

public class EtwEventCollector : IEventCollector
{
    private readonly ProcessCorrelationEngine _correlationEngine;
    private readonly IDiagnosticLogger _logger;
    private readonly Action<string, int, string>? _onFileModifiedForArtifact;
    private readonly InjectionDetector? _injectionDetector;

    private TraceEventSession? _kernelSession;
    private TraceEventSession? _userSession;
    private Thread? _kernelProcessingThread;
    private Thread? _userProcessingThread;
    private bool _isDisposed;
    private bool _isRunning;
    private long _nextEventId = 1;

    public string Name => "Windows Kernel ETW Provider";

    public bool IsSupported { get; private set; }

    public string StatusDescription { get; private set; } = "Not started";

    public event Action<AnalysisEvent>? EventEmitted;

    public EtwEventCollector(
        ProcessCorrelationEngine correlationEngine,
        IDiagnosticLogger logger,
        Action<string, int, string>? onFileModifiedForArtifact = null,
        InjectionDetector? injectionDetector = null)
    {
        _correlationEngine = correlationEngine;
        _logger = logger;
        _onFileModifiedForArtifact = onFileModifiedForArtifact;
        _injectionDetector = injectionDetector;

        CheckPrivileges();
    }

    private void CheckPrivileges()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (isAdmin)
            {
                IsSupported = true;
                StatusDescription = "Administrator privileges verified. Kernel ETW ready.";
            }
            else
            {
                IsSupported = false;
                StatusDescription = "Administrator privileges NOT detected. ETW kernel trace requires elevation.";
                _logger.Warn("ETW", "Application is running without Administrator privileges. Kernel ETW (File/Registry/Network) will be unavailable. Falling back to standard user monitoring.");
            }
        }
        catch (Exception ex)
        {
            IsSupported = false;
            StatusDescription = $"Privilege check failed: {ex.Message}";
            _logger.Error("ETW", "Failed to check administrative privileges", ex);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (!IsSupported)
        {
            _logger.Warn("ETW", "Skipping ETW session startup due to lack of administrative privileges.");
            return Task.CompletedTask;
        }

        if (_isRunning)
            return Task.CompletedTask;

        _isRunning = true;
        StatusDescription = "Starting ETW sessions...";

        try
        {
            string sessionPrefix = "ExeScope_" + Guid.NewGuid().ToString("N")[..8];
            string kernelSessionName = KernelTraceEventParser.KernelSessionName;
            string userSessionName = sessionPrefix + "_User";

            _kernelSession = new TraceEventSession(kernelSessionName, TraceEventSessionOptions.Create)
            {
                StopOnDispose = true,
                BufferSizeMB = 64,
                CircularBufferMB = 128
            };

            var kernelKeywords = KernelTraceEventParser.Keywords.Process
                                 | KernelTraceEventParser.Keywords.ImageLoad
                                 | KernelTraceEventParser.Keywords.Thread
                                 | KernelTraceEventParser.Keywords.FileIO
                                 | KernelTraceEventParser.Keywords.FileIOInit
                                 | KernelTraceEventParser.Keywords.Registry
                                 | KernelTraceEventParser.Keywords.NetworkTCPIP;

            _kernelSession.EnableKernelProvider(kernelKeywords);

            WireKernelEvents(_kernelSession.Source.Kernel);

            _kernelProcessingThread = new Thread(() =>
            {
                try
                {
                    _kernelSession.Source.Process();
                }
                catch (Exception ex)
                {
                    if (!_isDisposed)
                        _logger.Error("ETW", "Kernel session processing stopped unexpectedly", ex);
                }
            })
            {
                IsBackground = true,
                Name = "ExeScope_ETW_Kernel"
            };
            _kernelProcessingThread.Start();

            try
            {
                _userSession = new TraceEventSession(userSessionName, TraceEventSessionOptions.Create)
                {
                    StopOnDispose = true
                };

                var dnsProviderGuid = new Guid("1c950233-3226-4d62-acb6-697860136e4f");
                _userSession.EnableProvider(dnsProviderGuid, TraceEventLevel.Informational, 0x8000000000000000);

                _userSession.Source.Dynamic.All += HandleDynamicUserEvent;

                _userProcessingThread = new Thread(() =>
                {
                    try
                    {
                        _userSession.Source.Process();
                    }
                    catch (Exception ex)
                    {
                        if (!_isDisposed)
                            _logger.Error("ETW", "User session processing stopped unexpectedly", ex);
                    }
                })
                {
                    IsBackground = true,
                    Name = "ExeScope_ETW_User"
                };
                _userProcessingThread.Start();
            }
            catch (Exception ex)
            {
                _logger.Warn("ETW", $"DNS ETW provider could not be started: {ex.Message}");
            }

            StatusDescription = "Active (Recording Kernel ETW events)";
            _logger.Info("ETW", "Kernel and User ETW sessions successfully initialized and capturing.");
        }
        catch (Exception ex)
        {
            StatusDescription = $"Failed to start: {ex.Message}";
            _logger.Error("ETW", "Failed to start ETW sessions", ex);
        }

        return Task.CompletedTask;
    }

    private void WireKernelEvents(KernelTraceEventParser kernel)
    {
        kernel.ProcessStart += data =>
        {
            var utcTime = data.TimeStamp.ToUniversalTime();
            int pid = data.ProcessID;
            int parentPid = data.ParentID;
            string imageFileName = data.ImageFileName ?? string.Empty;
            string commandLine = data.CommandLine ?? string.Empty;

            if (_correlationEngine.TryRegisterProcess(pid, parentPid, imageFileName, commandLine, utcTime, out var tracked))
            {
                var evt = new ProcessEvent
                {
                    EventId = Interlocked.Increment(ref _nextEventId),
                    TimestampUtc = utcTime,
                    ProcessId = pid,
                    ParentProcessId = parentPid,
                    ProcessImage = tracked?.ImageName ?? imageFileName,
                    ImagePath = tracked?.ImagePath ?? imageFileName,
                    CommandLine = commandLine,
                    EventType = ProcessEventType.Started,
                    Summary = $"Process started: {Path.GetFileName(imageFileName)} (PID: {pid}, Parent: {parentPid})"
                };
                Emit(evt);
            }
        };

        kernel.ProcessStop += data =>
        {
            var utcTime = data.TimeStamp.ToUniversalTime();
            int pid = data.ProcessID;
            int exitCode = data.ExitStatus;

            if (_correlationEngine.RegisterProcessExit(pid, utcTime, exitCode))
            {
                var evt = new ProcessEvent
                {
                    EventId = Interlocked.Increment(ref _nextEventId),
                    TimestampUtc = utcTime,
                    ProcessId = pid,
                    ProcessImage = data.ImageFileName ?? string.Empty,
                    EventType = ProcessEventType.Terminated,
                    ExitCode = exitCode,
                    Summary = $"Process terminated: {data.ImageFileName} (PID: {pid}, ExitCode: {exitCode})"
                };
                Emit(evt);
            }
        };

        kernel.FileIOCreate += data =>
        {
            HandleFileEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), FileOperationType.Create, data.FileName, "SUCCESS");
        };

        kernel.FileIOWrite += data =>
        {
            HandleFileEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), FileOperationType.Write, data.FileName, "SUCCESS",
                byteOffset: data.Offset, byteCount: data.IoSize);
        };

        kernel.FileIORead += data =>
        {
            HandleFileEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), FileOperationType.Read, data.FileName, "SUCCESS",
                byteOffset: data.Offset, byteCount: data.IoSize);
        };

        kernel.FileIORename += data =>
        {
            HandleFileEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), FileOperationType.Rename, data.FileName, "SUCCESS");
        };

        kernel.FileIOClose += data =>
        {
            HandleFileEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), FileOperationType.Close, data.FileName, "SUCCESS");
        };

        kernel.RegistryCreate += data =>
        {
            HandleRegistryEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), RegistryOperationType.CreateKey, data.KeyName, data.Status);
        };

        kernel.RegistryOpen += data =>
        {
            HandleRegistryEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), RegistryOperationType.OpenKey, data.KeyName, data.Status);
        };

        kernel.RegistryDelete += data =>
        {
            HandleRegistryEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), RegistryOperationType.DeleteKey, data.KeyName, data.Status);
        };

        kernel.RegistrySetValue += data =>
        {
            HandleRegistryEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), RegistryOperationType.SetValue, data.KeyName, data.Status, data.ValueName);
        };

        kernel.RegistryDeleteValue += data =>
        {
            HandleRegistryEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), RegistryOperationType.DeleteValue, data.KeyName, data.Status, data.ValueName);
        };

        kernel.TcpIpConnect += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.TCP, NetworkDirection.Outbound,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport, null);
        };

        kernel.TcpIpAccept += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.TCP, NetworkDirection.Inbound,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport, null);
        };

        kernel.TcpIpSend += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.TCP, NetworkDirection.Outbound,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport, data.size);
        };

        kernel.TcpIpRecv += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.TCP, NetworkDirection.Inbound,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport, data.size);
        };

        kernel.UdpIpSend += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.UDP, NetworkDirection.Outbound,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport, data.size);
        };

        kernel.UdpIpRecv += data =>
        {
            HandleNetworkEvent(data.ProcessID, data.TimeStamp.ToUniversalTime(), NetworkProtocol.UDP, NetworkDirection.Inbound,
                data.daddr?.ToString() ?? "0.0.0.0", data.dport,
                data.saddr?.ToString() ?? "0.0.0.0", data.sport, data.size);
        };

        kernel.ImageLoad += data =>
        {
            int pid = data.ProcessID;
            var utcTime = data.TimeStamp.ToUniversalTime();
            string fileName = data.FileName ?? string.Empty;
            ulong imageBase = (ulong)data.ImageBase;
            uint imageSize = (uint)data.ImageSize;

            if (_correlationEngine.IsProcessTracked(pid, utcTime, out var tracked))
            {
                _correlationEngine.RegisterModuleLoaded(pid, fileName, utcTime);

                var evt = new ProcessEvent
                {
                    EventId = Interlocked.Increment(ref _nextEventId),
                    TimestampUtc = utcTime,
                    ProcessId = pid,
                    ProcessImage = tracked?.ImageName ?? string.Empty,
                    EventType = ProcessEventType.ModuleLoaded,
                    ModulePath = fileName,
                    ModuleBaseAddress = imageBase,
                    ModuleSize = imageSize,
                    Summary = $"Module loaded: {Path.GetFileName(fileName)} (Base: 0x{imageBase:X}, Size: {imageSize})"
                };
                Emit(evt);
            }

            _injectionDetector?.OnImageLoadInAnyProcess(pid, fileName, imageBase, imageSize, utcTime);
        };

        kernel.ThreadStart += data =>
        {
            int pid = data.ProcessID;
            var utcTime = data.TimeStamp.ToUniversalTime();
            ulong startAddr = (ulong)data.Win32StartAddr;

            _injectionDetector?.OnThreadStartInExternalProcess(pid, startAddr, utcTime);
        };
    }

    private void HandleDynamicUserEvent(TraceEvent data)
    {
        // Check if event is from Microsoft-Windows-DNS-Client
        if (data.ProviderName.Equals("Microsoft-Windows-DNS-Client", StringComparison.OrdinalIgnoreCase))
        {
            int pid = data.ProcessID;
            var utcTime = data.TimeStamp.ToUniversalTime();

            if (_correlationEngine.IsProcessTracked(pid, utcTime, out var tracked))
            {
                string query = data.PayloadStringByName("QueryName") ?? string.Empty;
                string results = data.PayloadStringByName("QueryResults") ?? string.Empty;

                if (!string.IsNullOrEmpty(query))
                {
                    var evt = new NetworkEvent
                    {
                        EventId = Interlocked.Increment(ref _nextEventId),
                        TimestampUtc = utcTime,
                        ProcessId = pid,
                        ProcessImage = tracked?.ImageName ?? string.Empty,
                        Protocol = NetworkProtocol.DNS,
                        Direction = NetworkDirection.Outbound,
                        DnsQuery = query,
                        DnsResponse = results,
                        CorrelationMethod = NetworkCorrelationMethod.DnsClientCorrelation,
                        Confidence = "High",
                        Summary = $"DNS Query: {query} -> {results}"
                    };
                    Emit(evt);
                }
            }
        }
    }

    private void HandleFileEvent(int pid, DateTime utcTime, FileOperationType op, string? fileName, string status, long? byteOffset = null, long? byteCount = null)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return;

        if (_correlationEngine.IsProcessTracked(pid, utcTime, out var tracked))
        {
            var evt = new FileEvent
            {
                EventId = Interlocked.Increment(ref _nextEventId),
                TimestampUtc = utcTime,
                ProcessId = pid,
                ProcessImage = tracked?.ImageName ?? string.Empty,
                Operation = op,
                Path = fileName,
                Result = status,
                ByteOffset = byteOffset,
                ByteCount = byteCount,
                HasCapturedBytes = false,
                Summary = $"File {op}: {fileName} ({status})"
            };
            Emit(evt);

            // If file was created, written, or renamed, signal artifact collector
            if (op is FileOperationType.Create or FileOperationType.Write or FileOperationType.Rename)
            {
                _onFileModifiedForArtifact?.Invoke(fileName, pid, tracked?.ImageName ?? string.Empty);
                _injectionDetector?.OnFileWriteByTrackedProcess(pid, fileName, utcTime);
            }
        }
    }

    private void HandleRegistryEvent(int pid, DateTime utcTime, RegistryOperationType op, string? keyName, int status, string? valueName = null)
    {
        if (string.IsNullOrWhiteSpace(keyName))
            return;

        if (_correlationEngine.IsProcessTracked(pid, utcTime, out var tracked))
        {
            string statusStr = status == 0 ? "SUCCESS" : $"0x{status:X8}";
            var evt = new RegistryEvent
            {
                EventId = Interlocked.Increment(ref _nextEventId),
                TimestampUtc = utcTime,
                ProcessId = pid,
                ProcessImage = tracked?.ImageName ?? string.Empty,
                Operation = op,
                KeyPath = keyName,
                ValueName = valueName,
                Result = statusStr,
                Summary = $"Registry {op}: {keyName}{(string.IsNullOrEmpty(valueName) ? "" : $"\\{valueName}")}"
            };
            Emit(evt);
        }
    }

    private void HandleNetworkEvent(int pid, DateTime utcTime, NetworkProtocol proto, NetworkDirection dir,
        string localAddr, int localPort, string remoteAddr, int remotePort, long? bytes)
    {
        if (_correlationEngine.IsProcessTracked(pid, utcTime, out var tracked))
        {
            string? note = remotePort == 443 ? "TLS encrypted stream (metadata preserved, payload not decrypted)" : null;

            var evt = new NetworkEvent
            {
                EventId = Interlocked.Increment(ref _nextEventId),
                TimestampUtc = utcTime,
                ProcessId = pid,
                ProcessImage = tracked?.ImageName ?? string.Empty,
                Protocol = proto,
                Direction = dir,
                LocalAddress = localAddr,
                LocalPort = localPort,
                RemoteAddress = remoteAddr,
                RemotePort = remotePort,
                BytesTransferred = bytes,
                CorrelationMethod = NetworkCorrelationMethod.ExactPidMatch,
                Confidence = "High",
                SecurityNotes = note,
                Summary = $"{proto} {dir}: {localAddr}:{localPort} <-> {remoteAddr}:{remotePort}" +
                          (bytes.HasValue ? $" ({bytes} bytes)" : "")
            };
            Emit(evt);
        }
    }

    private void Emit(AnalysisEvent evt)
    {
        try
        {
            EventEmitted?.Invoke(evt);
        }
        catch (Exception ex)
        {
            _logger.Error("ETW", "Error invoking event listener", ex);
        }
    }

    public Task StopAsync()
    {
        if (!_isRunning)
            return Task.CompletedTask;

        _isRunning = false;
        StatusDescription = "Stopped";

        try
        {
            _kernelSession?.Stop(noThrow: true);
            _userSession?.Stop(noThrow: true);

            _kernelProcessingThread?.Join(1000);
            _userProcessingThread?.Join(1000);

            _kernelSession?.Dispose();
            _kernelSession = null;

            _userSession?.Dispose();
            _userSession = null;
        }
        catch (Exception ex)
        {
            _logger.Error("ETW", "Error stopping ETW sessions", ex);
        }

        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
            return;

        _isDisposed = true;
        await StopAsync();
    }
}
