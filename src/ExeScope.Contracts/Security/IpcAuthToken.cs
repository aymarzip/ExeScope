using System.Security.Cryptography;
using System.Text;

namespace ExeScope.Contracts.Security;

public static class IpcAuthToken
{
    public const string HeaderName = "x-exescope-token";
    public const string DefaultNamedPipe = "ExeScopeAgentPipe";
    public const int DefaultTcpPort = 50051;

    public static string GenerateToken()
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static bool ValidateToken(string? candidate, string? expected)
    {
        if (string.IsNullOrEmpty(candidate) || string.IsNullOrEmpty(expected))
            return false;

        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate);
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);

        if (candidateBytes.Length != expectedBytes.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(candidateBytes, expectedBytes);
    }

    public static string GetDefaultTokenPath()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dir = Path.Combine(localAppData, "ExeScope");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "agent.token");
    }

    public static string LoadOrCreateToken(string? customPath = null)
    {
        string path = customPath ?? GetDefaultTokenPath();
        if (File.Exists(path))
        {
            try
            {
                string existing = File.ReadAllText(path).Trim();
                if (!string.IsNullOrEmpty(existing))
                    return existing;
            }
            catch
            {
                // Fallback to regeneration
            }
        }

        string newToken = GenerateToken();
        try
        {
            File.WriteAllText(path, newToken);
        }
        catch
        {
            // If read-only or restricted, proceed in-memory
        }

        return newToken;
    }
}
