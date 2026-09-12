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

        Console.WriteLine("[ExeScope TestTarget] Running main verification suite...");

        try
        {
            // 1. FILE OPERATIONS
            await PerformFileOperationsAsync();

            // 2. CHILD PROCESS
            PerformChildProcessLaunch();

            // 3. REGISTRY OPERATIONS
            PerformRegistryOperations();

            // 4. NETWORK OPERATIONS
            await PerformNetworkOperationsAsync();

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

        // Cleanup any leftovers
        try { if (File.Exists(testFile)) File.Delete(testFile); } catch { }
        try { if (File.Exists(renamedFile)) File.Delete(renamedFile); } catch { }
        try { if (File.Exists(toDeleteFile)) File.Delete(toDeleteFile); } catch { }

        // Create
        Console.WriteLine($"[File] Creating: {testFile}");
        await File.WriteAllTextAsync(testFile, "Initial content written by ExeScope TestTarget.\n");

        // Read
        string content = await File.ReadAllTextAsync(testFile);
        Console.WriteLine($"[File] Read: {content.Length} characters.");

        // Modify / Append
        Console.WriteLine($"[File] Modifying: {testFile}");
        await File.AppendAllTextAsync(testFile, $"Appended line at {DateTime.UtcNow:O}\n");

        // Rename
        Console.WriteLine($"[File] Renaming to: {renamedFile}");
        File.Move(testFile, renamedFile);

        // Read renamed
        string renamedContent = await File.ReadAllTextAsync(renamedFile);
        Console.WriteLine($"[File] Read renamed: {renamedContent.Length} characters.");

        // Create and delete temporary file
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
            // Create / Open SubKey under HKCU (safe, standard user accessible)
            Console.WriteLine($@"[Registry] Opening/Creating HKCU\{subKeyName}");
            using (var key = Registry.CurrentUser.CreateSubKey(subKeyName, writable: true))
            {
                if (key != null)
                {
                    // Set String Value
                    Console.WriteLine("[Registry] Setting value 'TestMarker' = 'DynamicAnalysisVerificationPassed'");
                    key.SetValue("TestMarker", "DynamicAnalysisVerificationPassed", RegistryValueKind.String);

                    // Set DWORD Value
                    Console.WriteLine("[Registry] Setting value 'LaunchCount' = 42");
                    key.SetValue("LaunchCount", 42, RegistryValueKind.DWord);

                    // Read Values
                    var val1 = key.GetValue("TestMarker");
                    var val2 = key.GetValue("LaunchCount");
                    Console.WriteLine($"[Registry] Verified values: TestMarker={val1}, LaunchCount={val2}");

                    // Delete Value
                    Console.WriteLine("[Registry] Deleting value 'TestMarker'");
                    key.DeleteValue("TestMarker", throwOnMissingValue: false);
                }
            }

            // Delete SubKey
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
}
