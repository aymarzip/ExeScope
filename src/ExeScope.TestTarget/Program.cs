using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Win32;

namespace ExeScope.TestTarget;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        int pid = Environment.ProcessId;
        Console.WriteLine($"[ExeScope TestTarget] Process started. PID: {pid}, Args: {string.Join(" ", args)}");

        if (args.Length > 0 && args[0].Equals("--child", StringComparison.OrdinalIgnoreCase))
        {
            return RunChildTask(pid);
        }

        if (args.Length > 0 && args[0].Equals("--high-load", StringComparison.OrdinalIgnoreCase))
        {
            return await RunHighLoadTaskAsync(pid);
        }

        if (args.Any(a => a.Equals("--simulate-injection", StringComparison.OrdinalIgnoreCase)))
        {
            return await RunSimulateInjectionAsync(pid);
        }

        Console.WriteLine("[ExeScope TestTarget] Running main verification suite...");

        try
        {
            await PerformFileOperationsAsync();
            PerformChildProcessLaunch();
            PerformRegistryOperations();
            await PerformNetworkOperationsAsync();
            await PerformSimulatedInjectionAsync();

            Console.WriteLine("[ExeScope TestTarget] All test operations completed successfully.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ExeScope TestTarget] Error during test execution: {ex}");
            return 1;
        }
    }

    private static int RunChildTask(int pid)
    {
        Console.WriteLine($"[ExeScope TestTarget CHILD] Child worker active. PID: {pid}");
        string childFile = Path.Combine(Path.GetTempPath(), $"exescope_child_{pid}.tmp");

        try
        {
            File.WriteAllText(childFile, $"Child process output at {DateTime.UtcNow:O}");
            string readBack = File.ReadAllText(childFile);
            Console.WriteLine($"[ExeScope TestTarget CHILD] File written and verified: {readBack.Length} bytes.");
            File.Delete(childFile);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ExeScope TestTarget CHILD] Error: {ex.Message}");
            return 2;
        }

        Thread.Sleep(300);
        Console.WriteLine("[ExeScope TestTarget CHILD] Child worker finished cleanly.");
        return 0;
    }

    private static async Task PerformFileOperationsAsync()
    {
        Console.WriteLine("\n--- 1. File Operations ---");
        string tempDir = Path.GetTempPath();
        string testFile = Path.Combine(tempDir, "exescope_test_artifact.txt");
        string renamedFile = Path.Combine(tempDir, "exescope_test_artifact_renamed.txt");
        string toDeleteFile = Path.Combine(tempDir, "exescope_delete_me.tmp");

        try { if (File.Exists(testFile)) File.Delete(testFile); } catch { }
        try { if (File.Exists(renamedFile)) File.Delete(renamedFile); } catch { }
        try { if (File.Exists(toDeleteFile)) File.Delete(toDeleteFile); } catch { }

        Console.WriteLine($"[File] Creating: {testFile}");
        await File.WriteAllTextAsync(testFile, "Initial content written by ExeScope TestTarget.\n");

        string content = await File.ReadAllTextAsync(testFile);
        Console.WriteLine($"[File] Read: {content.Length} characters.");

        Console.WriteLine($"[File] Modifying: {testFile}");
        await File.AppendAllTextAsync(testFile, $"Appended line at {DateTime.UtcNow:O}\n");

        Console.WriteLine($"[File] Renaming to: {renamedFile}");
        File.Move(testFile, renamedFile);

        string renamedContent = await File.ReadAllTextAsync(renamedFile);
        Console.WriteLine($"[File] Read renamed: {renamedContent.Length} characters.");

        Console.WriteLine($"[File] Creating temporary file: {toDeleteFile}");
        await File.WriteAllTextAsync(toDeleteFile, "Temporary data to be deleted.");

        Console.WriteLine($"[File] Deleting temporary file: {toDeleteFile}");
        File.Delete(toDeleteFile);
    }

    private static void PerformChildProcessLaunch()
    {
        Console.WriteLine("\n--- 2. Child Process Launch ---");
        string selfPath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "ExeScope.TestTarget.exe";

        Console.WriteLine($"[Process] Spawning child process: {selfPath} --child");
        var psi = new ProcessStartInfo
        {
            FileName = selfPath,
            Arguments = "--child",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var child = Process.Start(psi);
        if (child != null)
        {
            Console.WriteLine($"[Process] Child launched successfully. Child PID: {child.Id}");
            string output = child.StandardOutput.ReadToEnd();
            child.WaitForExit(5000);
            Console.WriteLine($"[Process] Child exited with code: {child.ExitCode}. Output: {output.Trim()}");
        }
        else
        {
            Console.WriteLine("[Process] Failed to launch child process.");
        }
    }

    private static void PerformRegistryOperations()
    {
        Console.WriteLine("\n--- 3. Registry Operations ---");
        const string subKeyName = @"Software\ExeScopeTest";

        try
        {
            Console.WriteLine($@"[Registry] Opening/Creating HKCU\{subKeyName}");
            using (var key = Registry.CurrentUser.CreateSubKey(subKeyName, writable: true))
            {
                if (key != null)
                {
                    Console.WriteLine("[Registry] Setting value 'TestMarker' = 'DynamicAnalysisVerificationPassed'");
                    key.SetValue("TestMarker", "DynamicAnalysisVerificationPassed", RegistryValueKind.String);

                    Console.WriteLine("[Registry] Setting value 'LaunchCount' = 42");
                    key.SetValue("LaunchCount", 42, RegistryValueKind.DWord);

                    var val1 = key.GetValue("TestMarker");
                    var val2 = key.GetValue("LaunchCount");
                    Console.WriteLine($"[Registry] Verified values: TestMarker={val1}, LaunchCount={val2}");

                    Console.WriteLine("[Registry] Deleting value 'TestMarker'");
                    key.DeleteValue("TestMarker", throwOnMissingValue: false);
                }
            }

            Console.WriteLine($@"[Registry] Cleaning up test key HKCU\{subKeyName}");
            Registry.CurrentUser.DeleteSubKey(subKeyName, throwOnMissingSubKey: false);
            Console.WriteLine("[Registry] Registry operations completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Registry] Registry note (non-critical if restricted): {ex.Message}");
        }
    }

    private static async Task PerformNetworkOperationsAsync()
    {
        Console.WriteLine("\n--- 4. Local Network Communication ---");
        const int port = 58421;
        string prefix = $"http://127.0.0.1:{port}/";

        using var listener = new HttpListener();
        try
        {
            listener.Prefixes.Add(prefix);
            listener.Start();
            Console.WriteLine($"[Network] Local HTTP listener active on {prefix}");

            var serverTask = Task.Run(async () =>
            {
                var context = await listener.GetContextAsync();
                var req = context.Request;
                byte[] responseBytes = Encoding.UTF8.GetBytes("ExeScope test response: OK");
                context.Response.ContentLength64 = responseBytes.Length;
                await context.Response.OutputStream.WriteAsync(responseBytes);
                context.Response.OutputStream.Close();
                Console.WriteLine($"[Network Server] Handled request: {req.HttpMethod} {req.Url}");
            });

            // Make HTTP request using HttpClient
            using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) })
            {
                Console.WriteLine($"[Network Client] Sending GET {prefix}test...");
                var response = await client.GetAsync($"{prefix}test");
                string body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[Network Client] Received response: {response.StatusCode} Body: '{body}'");
            }

            await serverTask;
        }
        catch (HttpListenerException hEx)
        {
            Console.WriteLine($"[Network] HttpListener note: {hEx.Message}. Performing TCP socket test instead.");
            await PerformTcpFallbackAsync(port);
        }
        finally
        {
            try { listener.Stop(); } catch { }
        }
    }

    private static async Task PerformTcpFallbackAsync(int port)
    {
        var tcpListener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, port);
        tcpListener.Start();

        var serverTask = Task.Run(async () =>
        {
            using var client = await tcpListener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            byte[] msg = Encoding.UTF8.GetBytes("PING-PONG");
            await stream.WriteAsync(msg);
        });

        using (var client = new System.Net.Sockets.TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, port);
            using var stream = client.GetStream();
            byte[] buf = new byte[32];
            int read = await stream.ReadAsync(buf);
            Console.WriteLine($"[Network TCP] Received {read} bytes fallback response.");
        }

        await serverTask;
        tcpListener.Stop();
    }

    private static async Task<int> RunHighLoadTaskAsync(int pid)
    {
        Console.WriteLine($"[ExeScope TestTarget HIGH-LOAD] Generating high-volume file and registry activity. PID: {pid}");
        string tempDir = Path.GetTempPath();

        for (int i = 0; i < 500; i++)
        {
            string f = Path.Combine(tempDir, $"exescope_load_{pid}_{i}.tmp");
            await File.WriteAllTextAsync(f, $"High load test line {i} at {DateTime.UtcNow:O}");
            File.Delete(f);
        }

        Console.WriteLine($"[ExeScope TestTarget HIGH-LOAD] High load burst completed.");
        return 0;
    }

    private static async Task<int> RunSimulateInjectionAsync(int pid)
    {
        Console.WriteLine($"[ExeScope TestTarget INJECTION] Running dedicated DLL injection simulation. PID: {pid}");
        await PerformSimulatedInjectionAsync();
        Console.WriteLine("[ExeScope TestTarget INJECTION] Simulation completed successfully.");
        return 0;
    }

    private static async Task PerformSimulatedInjectionAsync()
    {
        Console.WriteLine("\n--- 5. DLL Drop & Injection Simulation ---");
        string tempDir = Path.GetTempPath();
        string droppedDllPath = Path.Combine(tempDir, "exescope_injected_payload.dll");

        try
        {
            if (File.Exists(droppedDllPath))
            {
                try { File.Delete(droppedDllPath); } catch { }
            }

            byte[] dllBytes = GetSampleDllBytes();

            Console.WriteLine($"[Injection] Dropping payload DLL: {droppedDllPath} ({dllBytes.Length} bytes)");
            await File.WriteAllBytesAsync(droppedDllPath, dllBytes);

            await Task.Delay(200);

            Console.WriteLine("[Injection] Simulating external process loading the dropped DLL via rundll32...");
            bool launchedViaCom = TryLaunchExternalViaCom("rundll32.exe", $"\"{droppedDllPath}\",#1");
            if (!launchedViaCom)
            {
                bool launchedViaWmi = TryLaunchExternalViaWmi("rundll32.exe", $"\"{droppedDllPath}\",#1");
                if (!launchedViaWmi)
                {
                    LaunchDirectFallback("rundll32.exe", $"\"{droppedDllPath}\",#1");
                }
            }

            // Give ETW and Artifact Collector time to capture and archive
            await Task.Delay(1000);
            Console.WriteLine("[Injection] DLL drop and load simulation sequence completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Injection] Simulation note: {ex.Message}");
        }
        finally
        {
            try
            {
                if (File.Exists(droppedDllPath))
                {
                    File.Delete(droppedDllPath);
                }
            }
            catch { }
        }
    }

    private static byte[] GetSampleDllBytes()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var localDlls = Directory.GetFiles(baseDir, "*.dll");
        if (localDlls.Length > 0)
        {
            try
            {
                return File.ReadAllBytes(localDlls[0]);
            }
            catch { }
        }

        string systemDll = Path.Combine(Environment.SystemDirectory, "version.dll");
        if (File.Exists(systemDll))
        {
            try
            {
                return File.ReadAllBytes(systemDll);
            }
            catch { }
        }

        return Encoding.UTF8.GetBytes("MZ_EXESCOPE_SIMULATED_PAYLOAD_DLL");
    }

    private static bool TryLaunchExternalViaCom(string executable, string arguments)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("Shell.Application");
            if (shellType == null) return false;
            dynamic? shell = Activator.CreateInstance(shellType);
            if (shell == null) return false;
            shell.ShellExecute(executable, arguments, "", "open", 0);
            Console.WriteLine("[Injection] External loader dispatched via Explorer Shell COM.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Injection] COM launch note: {ex.Message}");
            return false;
        }
    }

    private static bool TryLaunchExternalViaWmi(string executable, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{executable} {arguments}'}}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
            bool success = p != null && p.ExitCode == 0;
            if (success)
            {
                Console.WriteLine("[Injection] External loader dispatched via WMI Win32_Process.");
            }
            return success;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Injection] WMI launch note: {ex.Message}");
            return false;
        }
    }

    private static void LaunchDirectFallback(string executable, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = executable,
                Arguments = arguments,
                UseShellExecute = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(2000);
            Console.WriteLine("[Injection] External loader dispatched via direct ShellExecute fallback.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Injection] Direct fallback note: {ex.Message}");
        }
    }
}
